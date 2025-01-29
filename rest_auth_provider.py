# -*- coding: utf-8 -*-
#
# REST endpoint Authentication module for Matrix synapse
# Copyright (C) 2017 Kamax Sarl
#
# https://www.kamax.io/
#
# Modified by Anderson Nishihara to support email as username on login
# and the new module interface onSynapse v1.46
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# ORIGINAL https://github.com/anishihara/matrix-synapse-rest-password-provider

import hashlib
import io
import logging
import time
from typing import (
    TYPE_CHECKING,
)

import synapse
from synapse import module_api
from synapse.logging.context import make_deferred_yieldable
from synapse.types import UserID
from synapse.types import (
    create_requester,
)
from synapse.util import json_decoder
from twisted.web.client import readBody

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class RestConfig(object):
    endpoint = ''


class RestAuthProvider(object):

    def __init__(self, config, api: module_api):
        if not config.endpoint:
            raise RuntimeError('Missing endpoint config')

        self.api = api
        self.endpoint = config.endpoint
        self.config = config
        self._profile_handler = api._hs.get_profile_handler()
        self._media_repo = (
            api._hs.get_media_repository() if api._hs.config.media.can_load_media_repo else None
        )
        self._http_client = api._hs.get_proxied_blocklisted_http_client()
        self._media_repo = api._hs.get_media_repository()
        self._is_mine_server_name = api._hs.is_mine_server_name

        logger.info('Endpoint: %s', self.endpoint)

        # Используем m.login.password
        # Чтобы можно было заходить из существующих клиентов для отладки
        # Иначе могли бы сделать свой flow - m.login.partner
        # https://spec.matrix.org/v1.8/client-server-api/#authentication-types
        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("m.login.password", ("password",)): self.check_fps_account,
            }
        )

    async def check_fps_account(
            self,
            username: str,
            login_type: str,
            login_dict: "synapse.module_api.JsonDict",
    ):
        if login_type != "m.login.password":
            return None

        if username != "flatpartner":
            return None

        token = login_dict.get("password")
        user = await self.get_fps_account(token=token)
        if not user:
            return None
            
        logger.info(user)

        localpart = "flatpartner_" + str(user["id"])

        user_id = self.api.get_qualified_user_id(localpart)

        user_id = await self.initialize_matrix_user(localpart=localpart, user_id=user_id, user=user, token=token)
        if not user_id:
            return None
        return user_id, None

    async def get_fps_account(self, token):
        headers = {"Authorization": "Bearer " + token}
        uri = self.endpoint + '/auth/account'

        try:
            response = await self._http_client.request(
                method="POST",
                uri=uri,
                headers=headers,
            )

            resp_body = await make_deferred_yieldable(readBody(response))
            resp = json_decoder.decode(resp_body.decode("utf-8"))

        except Exception as e:
            reason = "Error to get profile"
            logger.warning(e)
            logger.warning(reason)
            raise RuntimeError(reason)

        if not isinstance(resp, dict):
            raise RuntimeError("The account endpoint returned an invalid JSON response.")

        if response.code < 200 or response.code >= 300:
            reason = "Error to get profile - " + response.code
            logger.warning(reason)
            raise RuntimeError(reason)

        if not resp["user"]:
            reason = "Invalid JSON data returned from REST endpoint"
            logger.warning(reason)
            raise RuntimeError(reason)

        return resp["user"]

    async def initialize_matrix_user(self, localpart, user_id, user, token):
        logger.info("User %s authenticated", localpart)

        canonical_uid = await self.api.check_user_exists(user_id)
        if not canonical_uid:
            logger.info("User %s does not exist yet, creating...", user_id)

            if localpart != localpart.lower():
                logger.info('User %s was cannot be created due to username lowercase policy', localpart)
                return None

            canonical_uid = await self.api.register_user(localpart=localpart)
            _, access_token, _, _ = await self.api.register_device(canonical_uid)
            logger.info("Registration based on REST data was successful for %s", canonical_uid)

        else:
            logger.info("User %s already exists, registration skipped", canonical_uid)

        canonical_uid = UserID.from_string(canonical_uid)

        if user["image"]:
            if user["image"]["full_size"]:
                await self.set_avatar(user_id, token, user["image"]["full_size"])

        if user["name"]:
            logger.info("Handling profile data")
            display_name = user["name"]

            store = self._profile_handler.store

            logger.info("Set displayName %s for %s", display_name, canonical_uid)

            await store.set_profile_displayname(canonical_uid, display_name)
        else:
            logger.info("No profile data")

        return user_id

    # Args:
    # user_id: matrix user ID in the form @localpart:domain as a string.
    # picture_https_url: HTTPS url for the picture image file.
    async def set_avatar(self, user_id: str, token: str, picture_uuid: str) -> bool:
        if self._media_repo is None:
            logger.info(
                "failed to set user avatar because out-of-process media repositories "
                "are not supported yet "
            )
            return False

        try:
            def is_allowed_mime_type(content_type: str) -> bool:
                if (
                        self._profile_handler.allowed_avatar_mimetypes
                        and content_type
                        not in self._profile_handler.allowed_avatar_mimetypes
                ):
                    return False
                return True

            uid = UserID.from_string(user_id)

            # download picture, enforcing size limit & mime type check
            picture = io.BytesIO()

            headers = {"Authorization": "Bearer " + token}
            url = self.endpoint + '/media/' + picture_uuid

            content_length, headers, uri, code = await self._http_client.get_file(
                url=url,
                output_stream=picture,
                max_size=self._profile_handler.max_avatar_size,
                headers=headers,
                is_allowed_content_type=is_allowed_mime_type,
            )

            if code != 200:
                raise Exception(
                    f"GET request to download sso avatar image returned {code}"
                )

            # upload name includes hash of the image file's content so that we can
            # easily check if it requires an update or not, the next time user logs in
            upload_name = "flatpartner_" + hashlib.sha256(picture.read()).hexdigest()

            # bail if user already has the same avatar
            profile = await self._profile_handler.get_profile(user_id)
            if profile["avatar_url"] is not None:
                server_name = profile["avatar_url"].split("/")[-2]
                media_id = profile["avatar_url"].split("/")[-1]
                if self._is_mine_server_name(server_name):
                    media = await self._media_repo.store.get_local_media(media_id)
                    if media is not None and upload_name in media and upload_name == media.upload_name:
                        logger.info("skipping saving the user avatar")
                        return True

            # store it in media repository
            avatar_mxc_url = await self._media_repo.create_content(
                media_type=headers[b"Content-Type"][0].decode("utf-8"),
                upload_name=upload_name,
                content=picture,
                content_length=content_length,
                auth_user=uid,
            )

            # save it as user avatar
            await self._profile_handler.set_avatar_url(
                uid,
                create_requester(uid),
                str(avatar_mxc_url),
            )

            logger.info("successfully saved the user avatar")
            return True

        except Exception as exception:
            logger.warning(f"failed to save the user avatar2: {exception}", exc_info=True)
            return False

    @staticmethod
    def parse_config(config):
        # verify config sanity
        _require_keys(config, ["endpoint"])

        rest_config = RestConfig()
        rest_config.endpoint = config["endpoint"]

        return rest_config


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "REST Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )


def time_msec():
    """Get the current timestamp in milliseconds
    """
    return int(time.time() * 1000)
