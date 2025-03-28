# encoding:utf-8
import time
import threading
import json
import os
import requests
import re
import xml.etree.ElementTree as ET
import uuid
from common.log import logger
from bridge.context import ContextType
import plugins
from plugins import *
from config import conf
from lib.gewechat.client import GewechatClient
from channel.gewechat.gewechat_message import GeWeChatMessage
from plugins.event import EventContext, Event


@plugins.register(
    name="KeywordMonitor",
    desire_priority=100,
    hidden=False,
    enabled=False,
    desc="监控群聊关键词、URL链接和文件内容，记录违规次数，超时未撤回则踢出用户",
    version="0.9.2",
    author="mailkf",
)

## 该脚本适合DOW 0.1.25版，无需修改其他文件。直接放置到目录\plugins\KeywordMonitorPlugin中使用，配合插件目录中config.json文件。

class KeywordMonitorPlugin(Plugin):
    PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
    WARNING_FILE = os.path.join(PLUGIN_DIR, "user_warnings.json")

    def __init__(self):
        super().__init__()
        self.user_nickname_map = {}
        self.recalled_messages = set()
        self.recalled_messages_lock = threading.Lock()
        self.user_violations = {}
        self.running = False
        self.client = None
        self.app_id = None
        self.keywords = ["广告"]
        self.monitored_groups = []
        self.whitelist = []
        self.ignore_at_bot_msg = True
        self.enabled = False
        self.group_name_to_id = {}
        self.warning_records = {}
        self.warning_limit = 2
        self.url_check_enabled = False
        self.keyword_check_enabled = False
        self.file_check_enabled = False
        self.violation_timers = {}
        self.processed_recalls = set()

        try:
            self.config = super().load_config() or {}
            self.enabled = self.config.get("enabled", False)
            self.keywords = self.config.get("keywords", ["广告"])
            self.monitored_groups = self.config.get("monitored_groups", [])
            self.whitelist = self.config.get("whitelist", [])
            self.ignore_at_bot_msg = self.config.get("ignore_at_bot_msg", True)
            self.url_check_enabled = self.config.get("url_check_enabled", False)
            self.keyword_check_enabled = self.config.get("keyword_check_enabled", False)
            self.file_check_enabled = self.config.get("file_check_enabled", False)
            self.warning_limit = self.config.get("warning_limit", 2)

            self.AD_URL_PATTERNS = self.config.get("ad_url_patterns", [
                r'.*ad\.com.*',
                r'.*doubleclick\.net.*',
                r'.*googleads\.g\.doubleclick\.net.*',
                r'.*ads\.yahoo\.com.*',
                r'.*tracking\.com.*',
                r'.*affiliate\.com.*',
                r'.*promo\.com.*',
            ])
            self.UNSUPPORTED_URL_PATTERNS = self.config.get("unsupported_url_patterns", [
                r'.*finder\.video\.qq\.com.*',
                r'.*support\.weixin\.qq\.com/update.*',
                r'.*support\.weixin\.qq\.com/security.*',
                r'.*mp\.weixin\.qq\.com/mp/waerrpage.*',
            ])
            self.whitelist_urls = self.config.get("whitelist_urls", [r'.*wxapp\.tc\.qq\.com.*'])

            if not all(field in self.config for field in ["open_ai_api_key", "open_ai_api_base", "model"]):
                raise Exception("配置文件中缺少 OpenAI 必要参数 (open_ai_api_key, open_ai_api_base, model)")

            if conf().get("channel_type") != "gewechat":
                raise Exception("KeywordMonitor 插件仅支持 gewechat 渠道")

            base_url, token, app_id = conf().get("gewechat_base_url"), conf().get("gewechat_token"), conf().get("gewechat_app_id")
            if not all([base_url, token, app_id]):
                raise Exception("KeywordMonitor 插件需要配置 gewechat_base_url, gewechat_token 和 gewechat_app_id")

            self.client = GewechatClient(base_url, token)
            self.app_id = app_id

            self._load_group_mapping()
            self._load_warning_records()

            if self.enabled:
                self.running = True
                self.handlers[Event.ON_RECEIVE_MESSAGE] = self.on_handle_receive
                self.handlers["on_message_recall"] = self.on_handle_recall
                logger.info("[KeywordMonitor] 插件初始化成功，开始监控群聊关键词、URL链接和文件内容")
            else:
                logger.info("[KeywordMonitor] 插件未启用")

        except Exception as e:
            self.cleanup()
            logger.error(f"[KeywordMonitor] 初始化异常：{e}")
            raise e

    def on_handle_recall(self, e_context: EventContext):
        """处理消息撤回事件"""
        try:
            msg = e_context['context'].kwargs.get('msg')
            if not isinstance(msg, GeWeChatMessage):
                return

            content = str(msg.content) or msg._rawmsg.get('Data', {}).get('Content', {}).get('string', '')
            if not content:
                logger.error(f"[KeywordMonitor] 无法获取撤回消息内容: {msg.msg_id}")
                return

            newmsgid_match = re.search(r'<newmsgid>(\d+)</newmsgid>', content)
            if newmsgid_match:
                recalled_msg_id = newmsgid_match.group(1)
                with self.recalled_messages_lock:
                    self.recalled_messages.add(recalled_msg_id)
                    logger.info(f"[KeywordMonitor] 记录撤回消息ID: {recalled_msg_id}")
            else:
                logger.error(f"[KeywordMonitor] 未提取到newmsgid: {content[:200]}")
                self._handle_recall_message(msg)

        except Exception as e:
            logger.error(f"[KeywordMonitor] 处理撤回事件失败: {e}", exc_info=True)

    def on_handle_receive(self, e_context: EventContext):
        """处理接收到的消息"""
        context = e_context['context']
        if not context.kwargs.get('isgroup'):
            logger.debug("[KeywordMonitor] 非群聊消息，已忽略")
            return

        msg = context.kwargs.get('msg')
        if not isinstance(msg, GeWeChatMessage):
            logger.error("[KeywordMonitor] 消息对象不是 GeWeChatMessage 类型")
            return

        raw_msg_data = msg._rawmsg.get('Data', {})
        msg_type = raw_msg_data.get('MsgType')

        if msg_type == 10002 and "revokemsg" in (raw_msg_data.get('Content', {}).get('string', '')):
            newmsgid_match = re.search(r'<newmsgid>(\d+)</newmsgid>', raw_msg_data.get('Content', {}).get('string', ''))
            if newmsgid_match:
                recalled_msg_id = newmsgid_match.group(1)
                with self.recalled_messages_lock:
                    self.recalled_messages.add(recalled_msg_id)
                    self._check_and_process_recalled_message(recalled_msg_id, msg)
            return

        if context.type == ContextType.EMOJI:
            logger.info(f"[KeywordMonitor] 消息 {msg.msg_id} 是表情消息，已忽略")
            return
        if self._is_redpacket_message(msg):
            logger.info(f"[KeywordMonitor] 消息 {msg.msg_id} 是红包消息，已忽略检测")
            return
        if self.ignore_at_bot_msg and msg.is_at:
            logger.info(f"[KeywordMonitor] 消息 {msg.msg_id} 是@机器人的消息，已忽略")
            return

        sender_wxid, group_id, group_name = msg.actual_user_id, msg.from_user_id, msg.other_user_nickname
        if (self.monitored_groups and group_name not in self.monitored_groups):
            logger.info(f"[KeywordMonitor] 群 {group_name} 不在监控列表中，已忽略")
            return
        if sender_wxid in self.whitelist:
            logger.info(f"[KeywordMonitor] 发送者 {sender_wxid} 在白名单中，已忽略")
            return

        message_content = context.content
        warning_sent = False

        if self.keyword_check_enabled and any(keyword in message_content for keyword in self.keywords):
            self._handle_violation(sender_wxid, group_id, group_name, msg, "关键词违规")
            warning_sent = True

        if self.url_check_enabled and not warning_sent:
            urls = self._extract_all_links(message_content)
            for url in urls:
                if self.is_unsupported_url(url):
                    self._handle_violation(sender_wxid, group_id, group_name, msg, "（小程序/视频号）")
                    warning_sent = True
                    break
                if self.is_ad_url(url):
                    self._handle_violation(sender_wxid, group_id, group_name, msg, "广告链接")
                    warning_sent = True
                    break
                result = self._analyze_content(url)
                if result != "合规":
                    self._handle_violation(sender_wxid, group_id, group_name, msg, result)
                    warning_sent = True
                    break

        if self.file_check_enabled and context.type == ContextType.FILE and not warning_sent:
            file_content = self._extract_file_content(context.content)
            if file_content:
                result = self._analyze_content(file_content)
                if result != "合规":
                    self._handle_violation(sender_wxid, group_id, group_name, msg, result)

    def _load_group_mapping(self):
        """加载群名称到群ID的映射"""
        try:
            contacts = self.client.fetch_contacts_list(self.app_id)
            if contacts and contacts.get("data", {}).get("chatrooms"):
                for group in self.client.get_detail_info(self.app_id, contacts["data"]["chatrooms"])["data"]:
                    group_name = group.get("nickName", "")
                    group_id = group.get("userName", "")
                    if group_name and group_id:
                        self.group_name_to_id[group_name] = group_id
            logger.debug(f"[KeywordMonitor] 群名称到群ID的映射: {self.group_name_to_id}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 加载群映射失败: {e}")

    def _load_warning_records(self):
        """加载用户违规记录"""
        try:
            if os.path.exists(self.WARNING_FILE):
                with open(self.WARNING_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        self.warning_records = {k: int(v) if isinstance(v, (int, str)) else 0 for k, v in json.loads(content).items()}
                    else:
                        self.warning_records = {}
                        logger.warning("[KeywordMonitor] user_warnings.json 文件为空，初始化为空字典")
            else:
                self.warning_records = {}
                logger.info("[KeywordMonitor] user_warnings.json 文件不存在，初始化为空字典")
            logger.debug(f"[KeywordMonitor] 加载用户违规记录: {self.warning_records}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 加载违规记录失败: {e}")
            self.warning_records = {}

    def _save_warning_records(self):
        """保存用户违规记录"""
        try:
            with open(self.WARNING_FILE, "w", encoding="utf-8") as f:
                json.dump(self.warning_records, f, ensure_ascii=False, indent=4)
            logger.debug(f"[KeywordMonitor] 保存用户违规记录: {self.warning_records}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 保存违规记录失败: {e}")

    def _analyze_content(self, content):
        """分析内容是否包含违规信息"""
        prompt = (
            "请仔细分析以下内容，并判断是否包含以下违规信息：\n"
            "1. 广告（如未经授权的商业广告、营销信息等）\n"
            "2. 购物（如拼多多、淘宝、京东等购物平台链接，仅限非法推广）\n"
            "3. 赌博（如非法赌博网站、赌博游戏等）\n"
            "4. 反动（如政治敏感、违法信息等）\n"
            "5. 色情（如成人内容、淫秽信息等）\n"
            "\n"
            "请特别注意以下合规内容类型：\n"
            "- 普法宣传（如法律知识、法规解读、案例分析等）\n"
            "- 反诈骗宣传（如提醒用户警惕诈骗、普及防骗知识等）\n"
            "- 法律公告、法院通知或政府公告\n"
            "- 合法讨论或教育目的的内容\n"
            "\n"
            "请按以下格式返回结果：\n"
            "- 如果内容属于普法宣传，请返回：'合规'\n"
            "- 如果内容属于反诈骗宣传，请返回：'合规'\n"
            "- 如果内容属于法律公告、法院通知或政府公告，请返回：'合规'\n"
            "- 如果内容涉及合法讨论或教育目的，请返回：'合规'\n"
            "- 如果内容违规，返回：'违规类型: <类型>'（例如：'违规类型: 广告'）\n"
            "\n"
            "请严格按照以上格式返回结果，不要返回其他额外信息。\n"
            "\n"
            "内容：\n" + content
        )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config['open_ai_api_key']}"
        }
        payload = {
            "model": self.config["model"],
            "messages": [{"role": "user", "content": prompt}],
            "session_id": str(uuid.uuid4())
        }

        for attempt in range(2):
            try:
                response = requests.post(f"{self.config['open_ai_api_base']}/chat/completions", headers=headers, json=payload)
                response.raise_for_status()
                result = response.json()["choices"][0]["message"]["content"].strip()
                logger.info(f"[KeywordMonitor] 内容分析结果: {result}")
                return result
            except Exception as e:
                logger.error(f"[KeywordMonitor] 分析内容失败 (尝试 {attempt + 1}/2): {e}")
        logger.info("[KeywordMonitor] 重试次数用尽，返回默认合规")
        return "合规"

    def _extract_all_links(self, message_content):
        """提取消息中的所有链接"""
        xml_urls = re.findall(r'<url>(https?://[^\s]+)</url>', message_content)
        plain_urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message_content)
        urls = list(set(xml_urls + plain_urls))
        logger.info(f"[KeywordMonitor] 提取到的链接: {urls}")
        return urls

    def _extract_file_content(self, file_path):
        """提取文件内容"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"[KeywordMonitor] 文件路径不存在: {file_path}")
                return None
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            logger.info(f"[KeywordMonitor] 文件内容提取完成: {file_path}")
            return content
        except Exception as e:
            logger.error(f"[KeywordMonitor] 提取文件内容失败: {e}")
            return None

    def is_ad_url(self, url):
        """判断给定的 URL 是否包含广告内容"""
        return any(re.search(pattern, url) for pattern in self.AD_URL_PATTERNS)

    def is_unsupported_url(self, url):
        """判断给定的 URL 是否是不支持的 URL"""
        if any(re.search(pattern, url) for pattern in self.whitelist_urls):
            logger.info(f"[KeywordMonitor] URL {url} 在白名单中，已忽略")
            return False
        return any(re.search(pattern, url) for pattern in self.UNSUPPORTED_URL_PATTERNS)

    def _is_redpacket_message(self, msg):
        """判断消息是否为红包消息"""
        try:
            message_content = getattr(msg, 'content', '')
            return '<type><![CDATA[2001]]></type>' in message_content and '<title><![CDATA[微信红包]]></title>' in message_content
        except Exception as e:
            logger.error(f"[KeywordMonitor] 判断红包消息失败: {e}")
            return False

    def _handle_recall_message(self, msg):
        """处理撤回消息"""
        content = str(msg.content) or msg._rawmsg.get('Data', {}).get('Content', {}).get('string', '')
        if not content:
            logger.error("[KeywordMonitor] 无法获取撤回消息内容，处理失败")
            return

        newmsgid_match = re.search(r'<newmsgid>(\d+)</newmsgid>', content)
        if newmsgid_match:
            recalled_msg_id = newmsgid_match.group(1)
            with self.recalled_messages_lock:
                self.recalled_messages.add(recalled_msg_id)
                logger.info(f"[KeywordMonitor] 通过正则表达式提取并记录撤回消息ID: {recalled_msg_id}")
        else:
            try:
                xml_start = content.find('<sysmsg')
                if xml_start != -1:
                    root = ET.fromstring(content[xml_start:])
                    if root.tag == "sysmsg" and root.attrib.get("type") == "revokemsg":
                        newmsgid = root.find("revokemsg/newmsgid")
                        if newmsgid is not None and newmsgid.text:
                            with self.recalled_messages_lock:
                                self.recalled_messages.add(newmsgid.text)
                                logger.info(f"[KeywordMonitor] 通过XML解析记录撤回消息ID: {newmsgid.text}")
            except ET.ParseError as e:
                logger.error(f"[KeywordMonitor] XML 解析错误: {e}")

    def _handle_violation(self, sender_wxid, group_id, group_name, msg, violation_type):
        """处理违规行为"""
        self.warning_records.setdefault(sender_wxid, 0)
        self.warning_records[sender_wxid] += 1
        self.user_violations.setdefault(sender_wxid, []).append((str(msg.msg_id), violation_type))
        self._save_warning_records()
        
        user_display = f"{msg.actual_user_nickname}（{sender_wxid}）"
        group_display = f"{group_name}({group_id})"
        logger.info(f"[KeywordMonitor] 用户 {user_display} 违规次数更新为: {self.warning_records[sender_wxid]}")
        
        warning_msg = f"@{msg.actual_user_nickname} 请注意，您发送的内容包含违规信息：{violation_type}，请在2分钟内撤回消息，否则将被移出群聊。当前违规次数：{self.warning_records[sender_wxid]}"
        try:
            self.client.post_text(self.app_id, group_id, warning_msg, ats=sender_wxid)
            logger.info(f"[KeywordMonitor] 已警告用户 {user_display} 在群 {group_display}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 发送警告消息失败给用户 {user_display} 在群 {group_display}: {e}")
        
        self._start_countdown(sender_wxid, group_id, group_name, msg.msg_id, msg, violation_type)

    def _check_and_process_recalled_message(self, recalled_msg_id, msg):
        """检查并处理被撤回的消息，仅清理记录，不减少计数"""
        recalled_msg_id_str = str(recalled_msg_id)
        if recalled_msg_id_str in self.processed_recalls:
            logger.info(f"[KeywordMonitor] 撤回消息ID {recalled_msg_id_str} 已处理，跳过")
            return
        
        for user_id, violations in list(self.user_violations.items()):
            for v_msg_id, v_type in violations:
                if v_msg_id == recalled_msg_id_str:
                    self.user_violations[user_id] = [(mid, vtype) for mid, vtype in violations if mid != recalled_msg_id_str]
                    if not self.user_violations[user_id]:
                        del self.user_violations[user_id]
                    self.processed_recalls.add(recalled_msg_id_str)
                    user_display = f"{msg.actual_user_nickname}（{user_id}）"
                    group_display = f"{msg.other_user_nickname}({msg.from_user_id})"

                    logger.info(f"[KeywordMonitor] 用户 {user_display} 已撤回消息[{recalled_msg_id_str}]，等待倒计时检查是否超限")
                    return

    def _start_countdown(self, sender_wxid, group_id, group_name, violation_msg_id, msg, violation_type):
        """启动2分钟倒计时检查撤回并决定是否踢人"""
        def check_and_notify():
            violation_msg_id_str = str(violation_msg_id)
            user_display = f"{msg.actual_user_nickname}（{sender_wxid}）"
            group_display = f"{group_name}({group_id})"
            
            with self.recalled_messages_lock:
                if violation_msg_id_str not in self.recalled_messages:
                    # 未撤回消息，直接踢人
                    logger.info(f"[KeywordMonitor] 用户 {user_display} 未撤回消息[{violation_msg_id_str}]，2分钟后移出群聊 {group_display}")
                    self._kick_user(sender_wxid, group_id, group_name, violation_type, False, msg.actual_user_nickname)
                else:
                    # 已撤回但检查是否达到上限
                    if self.warning_records[sender_wxid] >= self.warning_limit:
                        logger.info(f"[KeywordMonitor] 用户 {user_display} 已撤回消息[{violation_msg_id_str}]，但违规次数达到上限 {self.warning_limit}，2分钟后将被踢出")
                        self._kick_user(sender_wxid, group_id, group_name, violation_type, True, msg.actual_user_nickname)
                    else:
                        # 发送感谢消息
                        thank_you_msg = f"@{msg.actual_user_nickname} 感谢您的理解与配合！在今后的交流中，还请您注意保持良好的聊天行为，营造友好和谐的沟通氛围。当前违规次数：{self.warning_records[sender_wxid]}"
                        try:
                            self.client.post_text(self.app_id, group_id, thank_you_msg, ats=sender_wxid)
                            logger.info(f"[KeywordMonitor] 已发送感谢消息给用户 {user_display} 在群 {group_display}")
                        except Exception as e:
                            logger.error(f"[KeywordMonitor] 发送感谢消息失败给用户 {user_display} 在群 {group_display}: {e}")
            
            if violation_msg_id_str in self.violation_timers:
                del self.violation_timers[violation_msg_id_str]
        
        timer = threading.Timer(120, check_and_notify)
        timer.start()
        self.violation_timers[str(violation_msg_id)] = timer
        user_display = f"{msg.actual_user_nickname}（{sender_wxid}）"
        group_display = f"{group_name}({group_id})"
        logger.info(f"[KeywordMonitor] 启动倒计时，用户: {user_display}, 消息ID: {violation_msg_id}, 群: {group_display}")

    def _kick_user(self, user_id, group_id, group_name, violation_type, exceed_limit, user_nickname=None):
        """将用户移出群聊（2分钟后执行）"""
        user_display = f"{user_nickname or '未知用户'}（{user_id}）"
        group_display = f"{group_name}({group_id})"
        logger.info(f"[KeywordMonitor] 2分钟后踢出用户 {user_display}，原因: {violation_type}, 超限: {exceed_limit}")
        try:
            response = self.client.remove_member(self.app_id, user_id, group_id)
            logger.info(f"[KeywordMonitor] remove_member API 返回: {response}")
            if exceed_limit:
                kick_msg = f"用户 {user_display} 因违规次数达到上限（违规类型: {violation_type}），将被移出群聊。"
            else:
                kick_msg = f"用户 {user_display} 因未在规定时间内撤回违规消息（违规类型: {violation_type}，次数: {self.warning_records[user_id]}），已被移出群聊 {group_display}。"
            self.client.post_text(self.app_id, group_id, kick_msg)
            logger.info(f"[KeywordMonitor] 已将用户 {user_display} 移出群聊 {group_display}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 移出用户 {user_display} 失败 在群 {group_display}: {e}")
            raise

    def get_help_text(self, **kwargs):
        """返回帮助文本"""
        help_text = "关键词、URL链接和文件内容监控插件。检测群聊中的关键词、URL链接和文件内容，记录违规次数，达到限制后踢出用户。\n"
        help_text += "配置项说明：\n"
        help_text += "- enabled: 是否启用插件（true/false，默认false）\n"
        help_text += "- keywords: 监控的关键词列表（例如：['广告', '推广']）\n"
        help_text += "- monitored_groups: 需要监控的群名称列表（为空则监控所有群）\n"
        help_text += "- whitelist: 白名单用户ID列表，忽略这些用户的消息\n"
        help_text += "- ignore_at_bot_msg: 是否忽略@机器人的消息（true/false，默认true）\n"
        help_text += "- url_check_enabled: 是否开启URL链接检测（true/false，默认false）\n"
        help_text += "- keyword_check_enabled: 是否开启关键词检测（true/false，默认false）\n"
        help_text += "- file_check_enabled: 是否开启文件内容检测（true/false，默认false）\n"
        help_text += "- warning_limit: 违规次数限制，达到此值将被踢出（默认2）\n"
        help_text += "注意：违规次数累计计算，即使撤回消息，次数也不会减少。\n"
        return help_text

    def cleanup(self):
        """清理资源"""
        self.running = False
        for timer in self.violation_timers.values():
            if timer.is_alive():
                timer.cancel()
        self.violation_timers.clear()

    def __del__(self):
        self.cleanup()
