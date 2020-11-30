from typing import Dict

from mitmproxy import http
from mitmproxy import ctx
import os
import re
import time
import json
import sys
import logging
from logging.handlers import RotatingFileHandler


class GetFlexTokens:
    def __init__(self):
        self.account = {
            'email': None,
            'password': None,
            'access-token': None,
            'refresh-token': None,
            'session-token': None,
            'frc-token': None,
            'instance-id': None,
            'cookies': None
        }
        self.data_complete = False
        self.num = 0

    def check_and_dump(self):
        if not self.account['email']:
            return
        else:
            os.makedirs(self.account['email'], exist_ok=True)

        filename = os.path.join(os.path.dirname(__file__), str(self.account["email"]), f'{int(time.time())}.json')
        self.save_data(filename, self.account)

        ctx.log.info(f'cookies and tokens have been saved for user: {self.account["email"]}')

    def response(self, flow: http.HTTPFlow) -> None:
        self.num = self.num + 1
        ctx.log.info("We've seen %d flows" % self.num)
        url = flow.request.url
        if 'https://api.amazon.com/auth/register' in url:
            print(' url found '.center(100, '*'))
            logger.info(' url found '.center(100, '*'))
            try:
                data = json.loads(str(flow.response.content, 'utf-8'))
                self.save_data(f'response-content.json', data)
                logger.info(data)
                response = data['response']['success']
                self.account['customer-info'] = response['extensions']['customer_info']
                self.account['customer-id'] = response['customer_id']
                self.account['access-token'] = response['tokens']['bearer']['access_token']
                self.account['refresh-token'] = response['tokens']['bearer']['refresh_token']
                self.account['cookies'] = response['tokens']['website_cookies']
            except Exception as e:
                logger.error(e)
                pass

            try:
                headers = flow.response.headers
                self.save_data(f'response-headers.json', json.loads(str(headers, 'utf-8')))
                logger.info(headers)
            except Exception as e:
                logger.error(e)

            try:
                cookies = flow.response.cookies
                self.save_data(f'response-cookies.json', dict(cookies))
                logger.info(cookies)
            except Exception as e:
                logger.error(e)
        self.check_and_dump()

    def request(self, flow: http.HTTPFlow) -> None:
        self.num = self.num + 1
        ctx.log.info("We've seen %d flows" % self.num)
        account = self.account
        url = flow.request.url
        if 'https://api.amazon.com/auth/register' in url:
            print(' url found '.center(100, '*'))
            logger.info(' url found '.center(100, '*'))
            try:
                data = json.loads(str(flow.request.content, 'utf-8'))
                self.save_data(f'request-content.json', data)
                try:
                    auth_data = data['auth_data']['user_id_password']
                    self.account['email'] = auth_data['user_id']
                    self.account['password'] = auth_data['password']
                    self.account['frc-token'] = data['user_context_map']['frc']
                except:
                    pass
            except:
                pass

            try:
                headers = flow.request.headers
                self.save_data(f'request-headers.json', json.loads(str(headers, 'utf-8')))
            except:
                pass

            try:
                cookies = dict(flow.request.cookies)
                self.save_data(f'request-cookies.json', cookies)
                self.account['session-token'] = cookies['session-token']
                self.account['session-id-time'] = cookies['session-id-time']
            except:
                pass

        # get instance id (referred as identi)
        if 'https://tas-na-extern.amazon.com/person' in url:
            try:
                self.account['instance-id'] = flow.request.headers.get('x-flex-instance-id')
            except:
                pass

            # get addition data about the user
            try:
                self.account['profile-data'] = json.loads(str(flow.response.content))['person']
            except:
                pass
        self.check_and_dump()

    @staticmethod
    def save_data(filename, data):
        os.makedirs('data', exist_ok=True)
        current_dir = os.path.dirname(__file__)
        file_path = os.path.join(current_dir, 'data', filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
    handlers=(
        RotatingFileHandler(
            filename='mitmdump.log',
            maxBytes=(1024 ** 3) / 2,  # max log file size 512MB
            backupCount=1,
        ),
    )
)

logger = logging.getLogger()

addons = [GetFlexTokens()]
