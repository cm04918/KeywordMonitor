# encoding:utf-8
import time
import queue
import threading
import json
import os
import requests
import re
import xml.etree.ElementTree as ET
from common.log import logger
from bridge.context import ContextType
import plugins
from plugins import *
from config import conf
from lib.gewechat.client import GewechatClient

@plugins.register(
    name="KeywordMonitor",
    desire_priority=100,
    hidden=False,
    enabled=False,
    desc="监控群聊关键词、URL链接和文件内容，自动移除发送者",
    version="0.9.1",
    author="mailkf",
)
class KeywordMonitorPlugin(Plugin):
    # 常量定义
    PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
    WARNING_FILE = os.path.join(PLUGIN_DIR, "user_warnings.json")  # 将 WARNING_FILE 定义移到类的顶层作用域
    AD_URL_PATTERNS = [
        r'.*ad\.com.*',  # 匹配包含 "ad.com" 的 URL
        r'.*doubleclick\.net.*',  # 匹配包含 "doubleclick.net" 的 URL
        r'.*googleads\.g\.doubleclick\.net.*',  # 匹配 Google Ads 的 URL
        r'.*ads\.yahoo\.com.*',  # 匹配 Yahoo Ads 的 URL
        r'.*tracking\.com.*',  # 匹配包含 "tracking.com" 的 URL
        r'.*affiliate\.com.*',  # 匹配包含 "affiliate.com"的 URL
        r'.*promo\.com.*',  # 匹配包含 "promo.com" 的 URL
    ]
    UNSUPPORTED_URL_PATTERNS = [
        r'.*finder\.video\.qq\.com.*',
        r'.*support\.weixin\.qq\.com/update.*',
        r'.*support\.weixin\.qq\.com/security.*',
        r'.*mp\.weixin\.qq\.com/mp/waerrpage.*',
    ]

    def __init__(self):
        super().__init__()
        self.recalled_messages = set()  # 用于存储撤回的消息ID
        self.user_violations = {}  # 用于存储每个用户的违规消息ID
        self.running = False
        self.client = None
        self.app_id = None
        self.keywords = ["广告"]  # 默认监控的关键词列表
        self.monitored_groups = []  # 默认监控的群列表（群名称）
        self.whitelist = []  # 默认白名单用户
        self.ignore_at_bot_msg = True  # 默认忽略@机器人的消息
        self.enabled = False  # 默认插件未启用
        self.group_name_to_id = {}  # 群名称到群ID的映射
        self.warning_records = {}  # 用户违规记录
        self.warning_limit = 2  # 默认警告次数限制
        self.url_check_enabled = False  # 是否开启URL检测
        self.keyword_check_enabled = False  # 是否开启关键词检测
        self.file_check_enabled = False  # 是否开启文件检测

        try:
            # 加载配置文件
            self.config = super().load_config()
            if not self.config:
                logger.warning("KeywordMonitor 插件配置文件不存在，使用默认配置")
            else:
                # 获取配置参数
                self.enabled = self.config.get("enabled", False)
                self.keywords = self.config.get("keywords", ["广告"])
                self.monitored_groups = self.config.get("monitored_groups", [])
                self.whitelist = self.config.get("whitelist", [])
                self.ignore_at_bot_msg = self.config.get("ignore_at_bot_msg", True)
                self.url_check_enabled = self.config.get("url_check_enabled", False)
                self.keyword_check_enabled = self.config.get("keyword_check_enabled", False)
                self.file_check_enabled = self.config.get("file_check_enabled", False)
                self.warning_limit = self.config.get("warning_limit", 2)

            # 检查是否是 gewechat 渠道
            if conf().get("channel_type") != "gewechat":
                raise Exception("KeywordMonitor 插件仅支持 gewechat 渠道")

            # 初始化 gewechat client
            base_url = conf().get("gewechat_base_url")
            token = conf().get("gewechat_token")
            app_id = conf().get("gewechat_app_id")

            if not all([base_url, token, app_id]):
                raise Exception("KeywordMonitor 插件需要配置 gewechat_base_url, gewechat_token 和 gewechat_app_id")

            self.client = GewechatClient(base_url, token)
            self.app_id = app_id

            # 获取群列表并建立群名称到群ID的映射
            self._load_group_mapping()

            # 加载用户违规记录
            self._load_warning_records()

            # 如果插件启用，则启动
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
            context = e_context['context']
            msg = context.kwargs.get('msg')
            if msg:
                self.recalled_messages.add(msg.msg_id)  # 记录撤回的消息ID
                logger.info(f"[KeywordMonitor] 消息 {msg.msg_id} 已被撤回")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 处理消息撤回事件失败: {e}")

    def _load_group_mapping(self):
        """加载群名称到群ID的映射"""
        try:
            contacts = self.client.fetch_contacts_list(self.app_id)
            if contacts and contacts.get("data"):
                chatrooms = contacts["data"].get("chatrooms", [])
                if chatrooms:
                    # 获取群聊详细信息
                    group_details = self.client.get_detail_info(self.app_id, chatrooms)
                    if group_details and group_details.get("data"):
                        for group in group_details["data"]:
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
                    file_content = f.read()
                    if file_content.strip():  # 检查文件内容是否为空
                        self.warning_records = json.loads(file_content)
                    else:
                        self.warning_records = {}  # 如果文件为空，初始化为空字典
                        logger.warning(f"[KeywordMonitor] user_warnings.json 文件为空，初始化为空字典")
            else:
                self.warning_records = {}  # 如果文件不存在，初始化为空字典
                logger.warning(f"[KeywordMonitor] user_warnings.json 文件不存在，初始化为空字典")
            logger.debug(f"[KeywordMonitor] 加载用户违规记录: {self.warning_records}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 加载用户违规记录失败: {e}")
            self.warning_records = {}  # 如果加载失败，初始化为空字典
            logger.warning(f"[KeywordMonitor] 加载用户违规记录失败，初始化为空字典")

    def _save_warning_records(self):
        """保存用户违规记录"""
        try:
            with open(self.WARNING_FILE, "w", encoding="utf-8") as f:
                json.dump(self.warning_records, f, ensure_ascii=False, indent=4)
            logger.debug(f"[KeywordMonitor] 保存用户违规记录: {self.warning_records}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 保存用户违规记录失败: {e}")

    def _analyze_content(self, content):
        """分析内容是否包含违规信息"""
        prompt = (
            "请分析以下内容，并判断是否包含以下违规信息：\n"
            "1. 广告（如商品推广、营销信息等）\n"
            "2. 购物（如拼多多、淘宝、京东等购物平台链接）\n"
            "3. 赌博（如赌博网站、赌博游戏等）\n"
            "4. 反动（如政治敏感、违法信息等）\n"
            "5. 色情（如色情内容、成人网站等）\n"
            "请按以下格式返回结果：\n"
            "- 如果内容合规，返回：'合规'\n"
            "- 如果内容违规，返回：'违规类型: <类型>'（例如：'违规类型: 广告'）\n"
            "内容：\n" + content
        )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {conf().get('open_ai_api_key')}"
        }

        payload = {
            "model": conf().get("model", "kimi-silent"),
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        try:
            logger.info(f"[KeywordMonitor] 开始分析内容: {content[:50]}...")  # 只记录前50个字符
            response = requests.post(f"{conf().get('open_ai_api_base')}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            if "choices" in response_data and len(response_data["choices"]) > 0:
                first_choice = response_data["choices"][0]
                if "message" in first_choice and "content" in first_choice["message"]:
                    result = first_choice["message"]["content"].strip()
                    logger.info(f"[KeywordMonitor] 内容分析结果: {result}")
                    return result
            logger.info(f"[KeywordMonitor] 内容分析结果: 合规")
            return "合规"
        except Exception as e:
            logger.error(f"[KeywordMonitor] 分析内容失败: {e}")
            return "合规"

    def _extract_all_links(self, message_content):
        """提取消息中的所有链接（包括网页分享、小程序等）"""
        url_pattern = re.compile(r'(https?://[^\s]+|www\.[^\s]+|[^\s]+\.(com|cn|net|org)[^\s]*)')
        urls = url_pattern.findall(message_content)
        extracted_urls = [url[0] for url in urls]
        logger.info(f"[KeywordMonitor] 提取到的链接: {extracted_urls}")
        return extracted_urls

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
        """判断给定的 URL 是否是不支持的 URL（如小程序、视频号等）"""
        return any(re.search(pattern, url) for pattern in self.UNSUPPORTED_URL_PATTERNS)

    def on_handle_receive(self, e_context: EventContext):
        context = e_context['context']
        logger.debug(f"[KeywordMonitor] 收到群聊消息: {context}")
        
        try:
            # 检查是否是群聊消息
            if not context.kwargs.get('isgroup'):
                return
        
            # 获取 GeWeChatMessage 对象
            msg = context.kwargs.get('msg')
            if not msg:
                logger.error("[KeywordMonitor] 无法获取消息对象")
                return
        
            # 打印 msg 对象的完整信息
            logger.info(f"[KeywordMonitor] msg 对象信息: {str(msg.__dict__)[:50]}")
        
            # 记录消息的详细信息
            message_type = getattr(msg, 'type', None)  # 尝试获取 type 属性
            if message_type is None:
                message_type = context.type  # 如果 type 属性不存在，使用 context.type
        
            logger.info(f"[KeywordMonitor] 消息详细信息: "
                        f"消息ID: {getattr(msg, 'msg_id', '未知')}, "
                        f"发送者ID: {getattr(msg, 'actual_user_id', '未知')}, "
                        f"发送者昵称: {getattr(msg, 'actual_user_nickname', '未知')}, "
                        f"群ID: {getattr(msg, 'from_user_id', '未知')}, "
                        f"群名称: {getattr(msg, 'other_user_nickname', '未知')}, "
                        f"消息类型: {message_type}, "
                        f"消息内容: {getattr(msg, 'content', '未知')[:100]}")
        
            # 如果配置了忽略@机器人的消息，则检查是否@机器人
            if self.ignore_at_bot_msg and msg.is_at:
                logger.info(f"[KeywordMonitor] 消息 {getattr(msg, 'msg_id', '未知')} 是@机器人的消息，已忽略")
                return
        
            # 获取消息内容、发送者ID和群ID
            message_content = context.content
            sender_wxid = getattr(msg, 'actual_user_id', '未知')
            group_id = getattr(msg, 'from_user_id', '未知')
        
            # 获取群名称
            group_name = getattr(msg, 'other_user_nickname', '未知')
        
            # 检查群是否在监控列表中
            if self.monitored_groups and group_name not in self.monitored_groups:
                logger.info(f"[KeywordMonitor] 群 {group_name} 不在监控列表中，已忽略")
                return
        
            # 检查发送者是否在白名单中
            if sender_wxid in self.whitelist:
                logger.info(f"[KeywordMonitor] 发送者 {sender_wxid} 在白名单中，已忽略")
                return
        
            # 检查消息类型是否为撤回消息
            if context.type == ContextType.REVOKE:  # 处理撤回消息
                self._handle_recall_message(msg)
                return
        
            # 检查消息内容是否包含关键词
            if self.keyword_check_enabled and any(keyword in message_content for keyword in self.keywords):
                self._handle_violation(sender_wxid, group_id, group_name, msg, "关键词违规")
        
            # 检查消息内容是否包含URL链接
            if self.url_check_enabled:
                urls = self._extract_all_links(message_content)
                for url in urls:
                    # 判断 URL 是否是不支持的 URL
                    if self.is_unsupported_url(url):
                        self._handle_violation(sender_wxid, group_id, group_name, msg, "（小程序/视频号）")
                        continue
        
                    # 判断 URL 是否包含广告内容
                    if self.is_ad_url(url):
                        self._handle_violation(sender_wxid, group_id, group_name, msg, "广告链接")
                        continue
        
                    # 分析URL内容
                    result = self._analyze_content(url)
                    if result != "合规":
                        self._handle_violation(sender_wxid, group_id, group_name, msg, result)
        
            # 检查消息内容是否包含文件
            if self.file_check_enabled and context.type == ContextType.FILE:
                file_path = context.content
                logger.info(f"[KeywordMonitor] 检测到文件消息，文件路径: {file_path}")
                file_content = self._extract_file_content(file_path)
                if file_content:
                    # 分析文件内容
                    result = self._analyze_content(file_content)
                    if result != "合规":
                        self._handle_violation(sender_wxid, group_id, group_name, msg, result)
                else:
                    logger.error(f"[KeywordMonitor] 文件内容提取失败: {file_path}")
        
        except Exception as e:
            logger.error(f"[KeywordMonitor] 处理消息异常: {e}")

    def _handle_recall_message(self, msg):
        """处理撤回消息"""
        try:
            # 解析消息内容中的 XML
            content = str(msg.content)  # 确保 content 是字符串类型
            logger.info(f"[KeywordMonitor] 收到撤回消息内容: {content}")
    
            # 尝试解析 XML
            try:
                # 清理 XML 内容，移除不必要的前缀或后缀
                xml_start = content.find('<sysmsg')
                if xml_start == -1:
                    logger.error(f"[KeywordMonitor] 撤回消息内容中未找到有效的 XML 部分: {content}")
                    return
    
                # 只保留 XML 部分
                content = content[xml_start:]
    
                # 检查 XML 是否完整
                if not content.endswith('</sysmsg>'):
                    logger.error(f"[KeywordMonitor] 撤回消息内容不完整: {content}")
                    return
    
                # 解析 XML
                root = ET.fromstring(content)
            except ET.ParseError as e:
                logger.error(f"[KeywordMonitor] 解析撤回消息 XML 失败: {e}")
                return
    
            # 检查是否是撤回消息
            if root.tag == "sysmsg" and root.attrib.get("type") == "revokemsg":
                revokemsg = root.find("revokemsg")
                if revokemsg is not None:
                    # 获取 newmsgid（与违规消息ID一致）
                    newmsgid = revokemsg.find("newmsgid").text
                    # 获取撤回提示信息
                    replacemsg = revokemsg.find("replacemsg").text if revokemsg.find("replacemsg") is not None else "未知用户撤回了一条消息"
                    logger.info(f"[KeywordMonitor] {replacemsg}, 消息ID: {newmsgid}")
    
                    # 记录撤回的消息ID（使用 newmsgid）
                    self.recalled_messages.add(str(newmsgid))  # 确保 newmsgid 是字符串类型
                    logger.info(f"[KeywordMonitor] 消息 {newmsgid} 已被撤回")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 处理撤回消息失败: {e}")
            
            
    def _handle_violation(self, sender_wxid, group_id, group_name, msg, violation_type):
        """处理违规行为"""
        # 更新用户违规记录
        if sender_wxid not in self.warning_records:
            self.warning_records[sender_wxid] = 0
        self.warning_records[sender_wxid] += 1
    
        # 记录用户的违规消息ID（使用 msg.msg_id）
        if sender_wxid not in self.user_violations:
            self.user_violations[sender_wxid] = []
        self.user_violations[sender_wxid].append(msg.msg_id)
        logger.info(f"[KeywordMonitor] 用户 {sender_wxid} 的违规消息ID: {msg.msg_id}")
    
        # 保存记录
        self._save_warning_records()
    
        # 发送警告消息，并@用户
        warning_msg = f"@{msg.actual_user_nickname} 请注意，您发送的内容包含违规信息：{violation_type}，请在2分钟内撤回消息，否则将被移出群聊。"
        try:
            # 使用 ats 参数来@用户
            self.client.post_text(self.app_id, group_id, warning_msg, ats=sender_wxid)
            logger.info(f"[KeywordMonitor] 已警告用户 {sender_wxid}")
        except Exception as e:
            logger.error(f"[KeywordMonitor] 发送警告消息失败: {e}")
    
        # 启动2分钟倒计时，检查用户是否撤回了违规消息
        self._start_countdown(sender_wxid, group_id, group_name, msg.msg_id, msg)  # 传递 msg 对象


    def _start_countdown(self, sender_wxid, group_id, group_name, violation_msg_id, msg):
        """启动2分钟倒计时，检查用户是否撤回了违规消息"""
        def check_and_remove():
            try:
                # 检查该用户的违规消息是否被撤回
                if str(violation_msg_id) not in self.recalled_messages:  # 确保消息ID是字符串类型
                    # 如果违规消息未被撤回，移除用户
                    logger.info(f"用户 {sender_wxid} 未在2分钟内撤回违规消息[{violation_msg_id}]，准备移除")
                    self.client.remove_member(self.app_id, sender_wxid, group_id)
                    logger.info(f"已移除用户 {sender_wxid} 从群 {group_name}")
                else:
                    # 如果违规消息已被撤回，发送感谢消息
                    logger.info(f"用户 {sender_wxid} 已撤回违规消息[{violation_msg_id}]，发送感谢消息")
                    thank_you_msg = f"@{msg.actual_user_nickname} 感谢您的理解与配合！在今后的交流中，还请您注意保持良好的聊天行为，营造友好和谐的沟通氛围。"
                    self.client.post_text(self.app_id, group_id, thank_you_msg, ats=sender_wxid)
                    logger.info(f"[KeywordMonitor] 已发送感谢消息给用户 {sender_wxid}")
            except Exception as e:
                logger.error(f"检查消息撤回状态或移除用户失败: {e}")
    
        # 启动2分钟倒计时
        timer = threading.Timer(120, check_and_remove)  # 120秒 = 2分钟
        timer.start()
    
    def _is_message_recalled(self, msg):
        """检查消息是否被撤回"""
        try:
            # 确保 msg 对象包含 msg_id 属性
            if not hasattr(msg, 'msg_id'):
                logger.error(f"[KeywordMonitor] 消息对象缺少 msg_id 属性")
                return False
    
            # 检查消息 ID 是否在 recalled_messages 集合中
            return str(msg.msg_id) in self.recalled_messages
        except Exception as e:
            logger.error(f"[KeywordMonitor] 检查消息撤回状态失败: {e}")
            return False

    def get_help_text(self, **kwargs):
        help_text = "关键词、URL链接和文件内容监控插件。检测群聊中的关键词、URL链接和文件内容，并自动移除发送者。\n"
        help_text += "配置项：\n"
        help_text += "- enabled: 是否启用插件（true/false）\n"
        help_text += "- keywords: 监控的关键词列表\n"
        help_text += "- monitored_groups: 监控的群名称列表\n"
        help_text += "- whitelist: 白名单用户ID列表\n"
        help_text += "- ignore_at_bot_msg: 是否忽略@机器人的消息（true/false）\n"
        help_text += "- url_check_enabled: 是否开启URL检测（true/false）\n"
        help_text += "- keyword_check_enabled: 是否开启关键词检测（true/false）\n"
        help_text += "- file_check_enabled: 是否开启文件检测（true/false）\n"
        help_text += "- warning_limit: 警告次数限制，达到次数后移除用户（默认2次）\n"
        return help_text

    def cleanup(self):
        """清理资源的方法"""
        if hasattr(self, 'running'):
            self.running = False

    def __del__(self):
        """析构函数调用清理方法"""
        self.cleanup()
