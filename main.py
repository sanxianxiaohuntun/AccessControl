from pkg.plugin.context import register, handler, BasePlugin, APIHost, EventContext
from pkg.plugin.events import PersonNormalMessageReceived, GroupNormalMessageReceived, PersonCommandSent, GroupCommandSent
from pkg.platform.types import message as platform_message
import yaml
import os

@register(name="bot访问权限控制(AccessControl)", description="管理员权限控制插件，支持私聊和群聊权限管理", version="0.1", author="小馄饨")
class AccessControlPlugin(BasePlugin):
    def __init__(self, host: APIHost):
        self.host = host
        self.config_file = "plugins/AccessControl/config.yaml"
        self.config = {
            "private_whitelist": [],  # 允许私聊的用户ID列表
            "group_whitelist": [],    # 允许的群组ID列表
            "group_user_whitelist": {},  # 群组内允许的用户ID列表，格式: {group_id: [user_ids]}
            "group_user_blacklist": {},  # 群组内禁止的用户ID列表，格式: {group_id: [user_ids]}
            "group_modes": {},  # 群组模式，格式: {group_id: "whitelist"/"blacklist"}
            "admins": []  # 管理员ID列表，可以修改配置
        }
        self._load_result = None  # 存储加载结果信息
        self.load_config()

    def load_config(self):
        """加载配置文件"""
        default_config = {
            "private_whitelist": [],
            "group_whitelist": [],
            "group_user_whitelist": {},
            "group_user_blacklist": {},
            "group_modes": {},
            "admins": []
        }
        
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r', encoding='utf-8') as f:
                loaded_config = yaml.safe_load(f)
                if loaded_config is None:
                    self.config = default_config
                else:
                    # 确保所有必需的字段都存在
                    self.config = default_config.copy()
                    self.config.update(loaded_config)
                    # 确保所有字段都存在
                    for key in default_config:
                        if key not in self.config:
                            self.config[key] = default_config[key]
                self._load_result = "loaded"  # 标记为已加载
        else:
            self.config = default_config
            self.save_config()
            self._load_result = "created"  # 标记为新创建

    async def initialize(self):
        """异步初始化，在这里打印配置信息"""
        await super().initialize()
        print(f"AccessControl插件初始化完成，当前配置：{self.config}")
        if self._load_result == "loaded":
            print(f"已加载配置文件：{self.config}")
        elif self._load_result == "created":
            print("配置文件不存在，已创建默认配置文件")

    def save_config(self):
        """保存配置文件"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, allow_unicode=True)

    def check_private_access(self, user_id: str) -> bool:
        """检查私聊权限"""
        user_id = str(user_id)
        print(f"检查私聊权限 - 用户ID: {user_id}")
        print(f"当前管理员列表: {self.config['admins']}")
        print(f"当前私聊白名单: {self.config['private_whitelist']}")
        
        # 确保管理员列表中的ID也是字符串
        admins = [str(admin_id) for admin_id in self.config["admins"]]
        private_whitelist = [str(user_id) for user_id in self.config["private_whitelist"]]
        
        if user_id in admins:
            print(f"用户 {user_id} 是管理员，允许访问")
            return True
            
        if user_id in private_whitelist:
            print(f"用户 {user_id} 在私聊白名单中，允许访问")
            return True
            
        print(f"用户 {user_id} 没有权限，拒绝访问")
        return False

    def check_group_access(self, group_id: str, user_id: str) -> bool:
        """检查群聊权限"""
        group_id = str(group_id)
        user_id = str(user_id)
        
        print(f"检查群聊权限 - 群ID: {group_id}, 用户ID: {user_id}")
        print(f"当前管理员列表: {self.config['admins']}")
        print(f"当前群聊白名单: {self.config['group_whitelist']}")
        print(f"当前群成员白名单: {self.config['group_user_whitelist']}")
        print(f"当前群成员黑名单: {self.config['group_user_blacklist']}")
        print(f"当前群组模式: {self.config['group_modes']}")
        
        # 确保所有ID都是字符串类型
        admins = [str(admin_id) for admin_id in self.config["admins"]]
        group_whitelist = [str(group_id) for group_id in self.config["group_whitelist"]]
        
        # 检查用户是否是管理员
        if user_id in admins:
            print(f"用户 {user_id} 是管理员，允许访问")
            return True
            
        # 检查群是否在白名单中
        if group_id not in group_whitelist:
            print(f"群 {group_id} 不在白名单中，拒绝访问")
            return False
            
        # 获取群组模式
        group_mode = self.config["group_modes"].get(group_id, "whitelist")  # 默认白名单模式
        
        if group_mode == "whitelist":
            # 白名单模式
            if group_id in self.config["group_user_whitelist"]:
                group_users = [str(uid) for uid in self.config["group_user_whitelist"][group_id]]
                is_allowed = user_id in group_users
                print(f"群 {group_id} 为白名单模式，用户 {user_id} {'在' if is_allowed else '不在'}白名单中")
                return is_allowed
            else:
                print(f"群 {group_id} 为白名单模式但没有用户白名单，拒绝访问")
                return False
        else:
            # 黑名单模式
            if group_id in self.config["group_user_blacklist"]:
                group_users = [str(uid) for uid in self.config["group_user_blacklist"][group_id]]
                is_blocked = user_id in group_users
                print(f"群 {group_id} 为黑名单模式，用户 {user_id} {'在' if is_blocked else '不在'}黑名单中")
                return not is_blocked
            else:
                print(f"群 {group_id} 为黑名单模式且没有用户黑名单，允许访问")
                return True

    @handler(PersonNormalMessageReceived)
    async def handle_private_message(self, ctx: EventContext):
        """处理私聊消息"""
        print(f"收到私聊消息 - 发送者ID: {ctx.event.sender_id}")
        
        # 检查是否是命令
        text = ctx.event.text_message.strip()
        if text.startswith('/ac ') or text == '/ac':
            print("检测到ac命令")
            # 解析命令和参数
            parts = text.split()
            params = parts[1:] if len(parts) > 1 else []
            
            # 阻止默认行为
            ctx.prevent_default()
            
            # 直接在这里处理命令
            sender_id = str(ctx.event.sender_id)
            
            # 检查是否是管理员
            if str(sender_id) not in [str(admin) for admin in self.config["admins"]]:
                print(f"用户 {sender_id} 不是管理员，拒绝执行命令")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain("只有管理员可以使用此命令。")
                ]))
                return

            print(f"用户 {sender_id} 是管理员，继续处理命令")
            
            try:
                await self._handle_command(ctx, params, is_group=False)
            except Exception as e:
                print(f"处理私聊命令时出错: {str(e)}")
                import traceback
                print(f"错误详情:\n{traceback.format_exc()}")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain(f"处理命令时出错: {str(e)}")
                ]))
            return
            
        # 非命令消息，检查权限
        if not self.check_private_access(ctx.event.sender_id):
            ctx.prevent_default()
            print("用户无私聊权限，消息已拦截")

    @handler(GroupNormalMessageReceived)
    async def handle_group_message(self, ctx: EventContext):
        """处理群聊消息"""
        print(f"收到群聊消息 - 群ID: {ctx.event.launcher_id}, 发送者ID: {ctx.event.sender_id}")
        
        # 检查是否是命令
        text = ctx.event.text_message.strip()
        if text.startswith('/ac ') or text == '/ac':
            print("检测到ac命令")
            # 解析命令和参数
            parts = text.split()
            params = parts[1:] if len(parts) > 1 else []
            
            # 阻止默认行为
            ctx.prevent_default()
            
            # 直接在这里处理命令
            sender_id = str(ctx.event.sender_id)
            
            # 检查是否是管理员
            if str(sender_id) not in [str(admin) for admin in self.config["admins"]]:
                print(f"用户 {sender_id} 不是管理员，拒绝执行命令")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain("只有管理员可以使用此命令。")
                ]))
                return

            print(f"用户 {sender_id} 是管理员，继续处理命令")
            
            try:
                await self._handle_command(ctx, params, is_group=True)
            except Exception as e:
                print(f"处理群聊命令时出错: {str(e)}")
                import traceback
                print(f"错误详情:\n{traceback.format_exc()}")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain(f"处理命令时出错: {str(e)}")
                ]))
            return
            
        # 非命令消息，检查权限
        if not self.check_group_access(ctx.event.launcher_id, ctx.event.sender_id):
            ctx.prevent_default()
            print("用户无群聊权限，消息已拦截")

    async def _handle_command(self, ctx: EventContext, params: list, is_group: bool):
        """统一的命令处理逻辑"""
        try:
            # 如果没有参数，显示帮助信息
            if not params or params[0] == "帮助":
                print("显示帮助信息")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain(
                        "AccessControl 插件命令帮助\n"
                        "═══════════════\n"
                        "【基础命令】\n"
                        "/ac 帮助 - 显示此帮助信息\n"
                        "/ac 查看配置 - 显示当前所有配置信息\n"
                        "\n"
                        "【管理员管理】\n"
                        "/ac 添加管理员 <用户ID> - 添加一个新的管理员\n"
                        "/ac 删除管理员 <用户ID> - 移除一个现有管理员\n"
                        "示例：/ac 添加管理员 2926253308\n"
                        "\n"
                        "【私聊权限管理】\n"
                        "/ac 添加私聊 <用户ID> - 允许指定用户私聊机器人\n"
                        "/ac 删除私聊 <用户ID> - 移除用户的私聊权限\n"
                        "示例：/ac 添加私聊 2926253308\n"
                        "\n"
                        "【群聊权限管理】\n"
                        "1. 群聊白名单：\n"
                        "/ac 添加群聊 <群ID> - 将群添加到白名单（默认白名单模式）\n"
                        "/ac 删除群聊 <群ID> - 将群从白名单移除\n"
                        "示例：/ac 添加群聊 348774756\n"
                        "\n"
                        "2. 群聊模式设置：\n"
                        "/ac 设置模式 <群ID> <白名单/黑名单> - 设置群的访问控制模式\n"
                        "示例：/ac 设置模式 348774756 黑名单\n"
                        "\n"
                        "3. 白名单模式下的用户管理：\n"
                        "/ac 添加群白名单 <群ID> <用户ID> - 允许指定用户访问\n"
                        "/ac 删除群白名单 <群ID> <用户ID> - 移除用户的访问权限\n"
                        "示例：/ac 添加群白名单 348774756 551865214\n"
                        "\n"
                        "4. 黑名单模式下的用户管理：\n"
                        "/ac 添加群黑名单 <群ID> <用户ID> - 禁止指定用户访问\n"
                        "/ac 删除群黑名单 <群ID> <用户ID> - 解除用户的访问限制\n"
                        "示例：/ac 添加群黑名单 348774756 551865214\n"
                        "\n"
                        "【使用说明】\n"
                        "1. 所有命令仅管理员可用\n"
                        "2. 群必须先添加到白名单才能进行其他操作\n"
                        "3. 白名单模式：仅白名单内用户可访问\n"
                        "4. 黑名单模式：除黑名单外的用户都可访问\n"
                        "5. 管理员不受任何限制\n"
                        "\n"
                        "【注意事项】\n"
                        "1. 删除群聊会同时清除该群所有配置\n"
                        "2. 建议定期使用 /ac 查看配置 检查设置\n"
                        "3. 修改配置后无需重启，立即生效"
                    )
                ]))
                return

            action = params[0]
            print(f"执行动作: {action}")

            # 处理查看配置命令
            if action == "查看配置":
                print("执行查看配置命令")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain(
                        f"当前配置：\n"
                        f"管理员：{self.config['admins']}\n"
                        f"私聊白名单：{self.config['private_whitelist']}\n"
                        f"群聊白名单：{self.config['group_whitelist']}\n"
                        f"群成员白名单：{self.config['group_user_whitelist']}\n"
                        f"群成员黑名单：{self.config['group_user_blacklist']}\n"
                        f"群组模式：{self.config['group_modes']}"
                    )
                ]))
                return

            # 其他命令都需要至少一个参数
            if len(params) < 2:
                print("参数不足")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain("参数不足")
                ]))
                return

            target_id = str(params[1])
            print(f"目标ID: {target_id}")

            # 处理各种命令
            if action == "添加群聊":
                print(f"添加群聊白名单: {target_id}")
                if target_id not in [str(x) for x in self.config["group_whitelist"]]:
                    self.config["group_whitelist"].append(int(target_id))
                    # 默认设置为白名单模式
                    self.config["group_modes"][target_id] = "whitelist"
                    self.save_config()
                    print(f"群聊白名单添加成功，当前白名单: {self.config['group_whitelist']}")
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"已添加群聊白名单：{target_id}，默认设置为白名单模式")
                    ]))
                else:
                    print(f"群ID {target_id} 已在白名单中")
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"群ID {target_id} 已在白名单中")
                    ]))
                return

            elif action == "添加管理员":
                print(f"添加管理员: {target_id}")
                if target_id not in [str(x) for x in self.config["admins"]]:
                    self.config["admins"].append(int(target_id))
                    self.save_config()
                    print(f"管理员添加成功，当前管理员列表: {self.config['admins']}")
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"已添加管理员：{target_id}")
                    ]))
                else:
                    print(f"用户 {target_id} 已是管理员")
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"用户 {target_id} 已是管理员")
                    ]))

            elif action == "删除管理员":
                print(f"移除管理员: {target_id}")
                if target_id in [str(x) for x in self.config["admins"]]:
                    self.config["admins"].remove(int(target_id))
                    self.save_config()
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"已移除管理员：{target_id}")
                    ]))

            elif action == "添加私聊":
                print(f"添加私聊白名单: {target_id}")
                if target_id not in [str(x) for x in self.config["private_whitelist"]]:
                    self.config["private_whitelist"].append(int(target_id))
                    self.save_config()
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"已添加私聊白名单：{target_id}")
                    ]))

            elif action == "删除私聊":
                print(f"移除私聊白名单: {target_id}")
                if target_id in [str(x) for x in self.config["private_whitelist"]]:
                    self.config["private_whitelist"].remove(int(target_id))
                    self.save_config()
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"已移除私聊白名单：{target_id}")
                    ]))

            elif action == "删除群聊":
                print(f"移除群聊白名单: {target_id}")
                if target_id in [str(x) for x in self.config["group_whitelist"]]:
                    self.config["group_whitelist"].remove(int(target_id))
                    # 同时清除相关配置
                    if target_id in self.config["group_modes"]:
                        del self.config["group_modes"][target_id]
                    if target_id in self.config["group_user_whitelist"]:
                        del self.config["group_user_whitelist"][target_id]
                    if target_id in self.config["group_user_blacklist"]:
                        del self.config["group_user_blacklist"][target_id]
                    self.save_config()
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"已移除群聊白名单：{target_id}")
                    ]))

            elif action == "设置模式":
                if len(params) < 3:
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain("请指定模式：白名单 或 黑名单")
                    ]))
                    return

                mode = "whitelist" if params[2] == "白名单" else "blacklist" if params[2] == "黑名单" else None
                if mode is None:
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain("模式只能是：白名单 或 黑名单")
                    ]))
                    return

                if target_id not in [str(x) for x in self.config["group_whitelist"]]:
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"群 {target_id} 不在白名单中，请先添加到群聊白名单")
                    ]))
                    return

                self.config["group_modes"][target_id] = mode
                self.save_config()
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain(f"已将群 {target_id} 设置为{params[2]}模式")
                ]))

            elif action in ["添加群白名单", "删除群白名单", "添加群黑名单", "删除群黑名单"]:
                if len(params) < 3:
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain("缺少用户ID参数")
                    ]))
                    return

                group_id = target_id
                user_id = str(params[2])

                # 检查群是否在白名单中
                if group_id not in [str(x) for x in self.config["group_whitelist"]]:
                    await ctx.reply(platform_message.MessageChain([
                        platform_message.Plain(f"群 {group_id} 不在白名单中，请先添加到群聊白名单")
                    ]))
                    return

                # 处理白名单操作
                if action.endswith("群白名单"):
                    if group_id not in self.config["group_user_whitelist"]:
                        self.config["group_user_whitelist"][group_id] = []

                    if action == "添加群白名单":
                        if user_id not in [str(x) for x in self.config["group_user_whitelist"][group_id]]:
                            self.config["group_user_whitelist"][group_id].append(int(user_id))
                            self.save_config()
                            await ctx.reply(platform_message.MessageChain([
                                platform_message.Plain(f"已添加群{group_id}的用户白名单：{user_id}")
                            ]))
                    else:  # 删除群白名单
                        if user_id in [str(x) for x in self.config["group_user_whitelist"][group_id]]:
                            self.config["group_user_whitelist"][group_id].remove(int(user_id))
                            self.save_config()
                            await ctx.reply(platform_message.MessageChain([
                                platform_message.Plain(f"已从群{group_id}的用户白名单中移除：{user_id}")
                            ]))

                # 处理黑名单操作
                else:
                    if group_id not in self.config["group_user_blacklist"]:
                        self.config["group_user_blacklist"][group_id] = []

                    if action == "添加群黑名单":
                        if user_id not in [str(x) for x in self.config["group_user_blacklist"][group_id]]:
                            self.config["group_user_blacklist"][group_id].append(int(user_id))
                            self.save_config()
                            await ctx.reply(platform_message.MessageChain([
                                platform_message.Plain(f"已添加群{group_id}的用户黑名单：{user_id}")
                            ]))
                    else:  # 删除群黑名单
                        if user_id in [str(x) for x in self.config["group_user_blacklist"][group_id]]:
                            self.config["group_user_blacklist"][group_id].remove(int(user_id))
                            self.save_config()
                            await ctx.reply(platform_message.MessageChain([
                                platform_message.Plain(f"已从群{group_id}的用户黑名单中移除：{user_id}")
                            ]))

            else:
                print(f"未知命令: {action}")
                await ctx.reply(platform_message.MessageChain([
                    platform_message.Plain("未知的命令")
                ]))

        except Exception as e:
            print(f"处理命令时出错: {str(e)}")
            import traceback
            print(f"错误详情:\n{traceback.format_exc()}")
            await ctx.reply(platform_message.MessageChain([
                platform_message.Plain(f"处理命令时出错: {str(e)}")
            ])) 