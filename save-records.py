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
            'identi': None,
            'cookie': None
        }
        self.num = 0

    def check_and_dump(self):
        # check if all the data is acquired, save the data in a file if true
        for value in self.account.values():
            if not value:
                return

        with open(f'{int(time.time())}-{self.account["email"]}.json', encoding='utf-8') as f:
            json.dump(self.account, f, indent=2)

        ctx.log.info(f'cookies and tokens have been saved for user: {self.account["email"]}')
        quit()

    def response(self, flow: http.HTTPFlow) -> None:
        self.num = self.num + 1
        ctx.log.info("We've seen %d flows" % self.num)
        account = self.account
        url = flow.request.url
        if 'https://api.amazon.com/auth/register' in url:
            print(' url found '.center(100, '*'))
            logger.info(' url found '.center(100, '*'))
            try:
                data = flow.response.content
                self.save_data(f'response-content.json', json.loads(str(data, 'utf-8')))
                logger.info(data)
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

    def request(self, flow: http.HTTPFlow) -> None:
        self.num = self.num + 1
        ctx.log.info("We've seen %d flows" % self.num)
        account = self.account
        url = flow.request.url
        if 'https://api.amazon.com/auth/register' in url:
            print(' url found '.center(100, '*'))
            logger.info(' url found '.center(100, '*'))
            try:
                data = flow.request.content
                self.save_data(f'request-content.json', json.loads(str(data, 'utf-8')))
            except:
                pass

            try:
                headers = flow.request.headers
                self.save_data(f'request-headers.json', json.loads(str(headers, 'utf-8')))
            except:
                pass

            try:
                cookies = flow.request.cookies
                self.save_data(f'request-cookies.json', dict(cookies))
            except:
                pass

    @staticmethod
    def save_data(filename, data):
        current_dir = os.path.dirname(__file__)
        file_path = os.path.join(current_dir, filename)
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
