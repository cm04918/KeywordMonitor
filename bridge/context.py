# encoding:utf-8

from enum import Enum


class ContextType(Enum):
    TEXT = 1  # 文本消息
    VOICE = 2  # 音频消息
    IMAGE = 3  # 图片消息
    FILE = 4  # 文件信息
    VIDEO = 5  # 视频信息
    SHARING = 6  # 分享信息

    IMAGE_CREATE = 10  # 创建图片命令
    ACCEPT_FRIEND = 19  # 同意好友请求
    JOIN_GROUP = 20  # 加入群聊
    PATPAT = 21  # 拍了拍
    FUNCTION = 22  # 函数调用
    EXIT_GROUP = 23  # 退出群聊

    NON_USER_MSG = 30  # 来自公众号、腾讯游戏、微信团队等非用户账号的消息
    STATUS_SYNC = 51  # 微信客户端的状态同步消息，可以忽略

    # 新增的消息类型
    REVOKE = 52  # 撤回消息
    FRIEND_REQUEST = 53  # 好友添加请求
    CONTACT_CARD = 54  # 名片消息
    EMOJI = 55  # 表情消息
    LOCATION = 56  # 地理位置消息
    FINDER_FEED = 57  # 视频号消息
    TRANSFER = 58  # 转账消息
    RED_PACKET = 59  # 红包消息
    GROUP_NOTIFICATION = 60  # 群聊通知（如修改群名、更换群主等）


    def __str__(self):
        return self.name


class Context:
    def __init__(self, type: ContextType = None, content=None, kwargs=dict()):
        self.type = type
        self.content = content
        self.kwargs = kwargs
        self.is_group = kwargs.get("is_group", False)  # 默认为私聊

        self.sender = kwargs.get("sender", None)  # 发送者
        self.receiver = kwargs.get("receiver", None)  # 接收者
        
    def is_group_message(self):
        return self.is_group
        
    def get_sender(self):
        return self.sender

    def get_receiver(self):
        return self.receiver

    def __contains__(self, key):
        if key == "type":
            return self.type is not None
        elif key == "content":
            return self.content is not None
        else:
            return key in self.kwargs

    def __getitem__(self, key):
        if key == "type":
            return self.type
        elif key == "content":
            return self.content
        else:
            return self.kwargs[key]

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def __setitem__(self, key, value):
        if key == "type":
            self.type = value
        elif key == "content":
            self.content = value
        else:
            self.kwargs[key] = value

    def __delitem__(self, key):
        if key == "type":
            self.type = None
        elif key == "content":
            self.content = None
        else:
            del self.kwargs[key]

    def __str__(self):
        return "Context(type={}, content={}, kwargs={})".format(self.type, self.content, self.kwargs)
        
    # 新增方法，用于处理不同类型的消息
    def is_text(self):
        return self.type == ContextType.TEXT

    def is_voice(self):
        return self.type == ContextType.VOICE

    def is_image(self):
        return self.type == ContextType.IMAGE

    def is_sharing(self):
        return self.type == ContextType.SHARING

    def is_revoke(self):
        return self.type == ContextType.REVOKE

    def is_friend_request(self):
        return self.type == ContextType.FRIEND_REQUEST

    def is_contact_card(self):
        return self.type == ContextType.CONTACT_CARD

    def is_emoji(self):
        return self.type == ContextType.EMOJI

    def is_location(self):
        return self.type == ContextType.LOCATION

    def is_finder_feed(self):
        return self.type == ContextType.FINDER_FEED

    def is_transfer(self):
        return self.type == ContextType.TRANSFER

    def is_red_packet(self):
        return self.type == ContextType.RED_PACKET

    def is_group_notification(self):
        return self.type == ContextType.GROUP_NOTIFICATION
