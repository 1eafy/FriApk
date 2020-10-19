

soName = {
    # 娜迦
    # "libchaosvmp.so": "娜迦",
    # "libddog.so": "娜迦",
    # "libfdog.so": "娜迦",
    # "libedog.so": "娜迦企业版",
    "娜迦": r"libchaosvmp\S*.so|lib\S*dog.so",

    # 爱加密
    # "libexec.so": "爱加密/腾讯",
    # "libexecmain.so": "爱加密",
    # "ijiami.dat": "爱加密",
    # "ijiami.ajm": "爱加密企业版",
    "爱加密": r"ijiami\S*.dat|libexec\S*.so|ijiami.ajm",

    # 梆梆
    # "libsecexe.so": "梆梆免费版",
    # "libsecmain.so": "梆梆免费版",
    # "libSecShell.so": "梆梆免费版",
    # "libDexHelper.so": "梆梆企业版",
    # "libDexHelper-x86.so": "梆梆企业版",
    "梆梆免费版": r"libsecexe\S*.so|libsecmain\S*.so|libSecShell\S*.so",
    "梆梆企业版": r"libDexHelper\S*.so",

    # 360
    # "libprotectClass.so": "360",
    # "libjiagu.so": "360",
    # "libjiagu_art.so": "360",
    # "libjiagu_x86.so": "360",
    "360加固": r"libjiagu\S*.so|libprotectClass\S*.so",

    # 通付盾
    # "libegis.so": "通付盾",
    # "libNSaferOnly.so": "通付盾",
    "通付盾加固": r"libegis\S*.so|libNSaferOnly\S*.so|libegismain\S*.so|libegisboot\S*.so",

    # "libnqshield.so": "网秦",
    "网秦加固": r"libnqshield\S*.so",
    # "libbaiduprotect.so": "百度",
    "百度加固": r"libbaiduprotect\S*.so",

    # 阿里聚安全
    # "aliprotect.so": "阿里聚安全",
    # "libsgmain.so": "阿里聚安全",
    # "libsgsecuritybody.so": "阿里聚安全",
    # "libmobisec.so": "阿里聚安全",
    "阿里聚安全": r"aliprotect.*.dat|libsgmain.so|libsgsecuritybody.so|libaliutils\S*.so|libmobisec\S*.so",

    # 腾讯
    # "libtup.so": "腾讯",
    # "libshell.so": "腾讯",
    # "mix.dex": "腾讯",
    # "mixz.dex": "腾讯",
    # "libtosprotection.armeabi.so": "腾讯御安全",
    # "libtosprotection.armeabi-v7a.so": "腾讯御安全",
    # "libtosprotection.x86.so": "腾讯御安全",
    # "libshell-super.2019.so": "腾讯御安全",
    "腾讯加固": r"^libup.so$|libshell\S*.so|mix\S*.dex|libtxRes\S*.so|libshell\S*.so",
    "腾讯御安全": r"libtosprotection\S*.so",

    # "libnesec.so": "网易易盾",
    "网易易盾加固": r"libnesec\S*.so|data.db|clazz.jar",
    # "libAPKProtect.so": "APKProtect",
    "APKProtect": r"libAPKProtect\S*.so",

    # 几维
    # "libkwscmm.so": "几维安全",
    # "libkwslinker.so": "几维安全",
    # "libkwscr.so": "几维安全",
    "几维安全": r"libkwscmm.so|libkwscr.so|libkwslinker.so",

    # "libx3g.so": "顶像科技",
    "顶像科技": r"libx3g.so",

    # "libapssec.so": "盛大",
    "盛大": r"libapssec.so",
    # "librsprotect.so": "瑞星",
    "瑞星": r"librsprotect.so",
}

"""
Normal permissions: 系统自动进行分配，不会需要用户主动确认是否授权
Signature permissions: 系统在app安装的时候，授予的权限。不会在app启动时弹出需要用户主动确认的权限
Special permissions: 需要进行动态判断的权限，客户需要主动确认是否赋予该权限,相同权限组中的权限，一但获取其中之一，整个权限组中的权限都将获取。
https://blog.csdn.net/zy987654zy/article/details/83026382
"""
allPermission = {
    "android.permission.ACCEPT_HANDOVER":
        {"description": "允许正在通话的应用程序继续在另一个应用程序中启动的通话。", "level": "D"},

    "android.permission.ACCESS_CHECKIN_PROPERTIES":
        {"description": "允许对checkin数据库中的“properties”表进行读/写访问，以更改上载的值。", "level": "N"},

    "android.permission.ACCESS_BACKGROUND_LOCATION":
        {"description": "允许应用在后台访问位置", "level": "D"},

    "android.permission.ACCESS_COARSE_LOCATION":
        {"description": "通过WiFi或移动基站的方式获取用户错略的经纬度信息:定位精度大概误差在30~1500米", "level": "D"},

    "android.permission.ACCESS_FINE_LOCATION":
        {"description": "通过GPS芯片接收卫星的定位信息:定位精度达10米以内", "level": "D"},

    "android.permission.ACCESS_MOCK_LOCATION":
        {"description": "获取模拟定位信息:一般用于帮助开发者调试应用", "level": "N"},

    "android.permission.ACCESS_NETWORK_STATE":
        {"description": "获取网络信息状态:如当前的网络连接是否有效", "level": "N"},

    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS":
        {
            "description": "允许应用程序访问其他位置提供程序命令。",
            "level": "N"
        },

    "android.permission.ACCESS_NOTIFICATION_POLICY":
        {"description": "通知 APP通知显示在状态栏",
         "level": "N"},

    "android.permission.ACCESS_MEDIA_LOCATION":
        {"description": "允许应用程序访问保存在用户共享集合中的任何地理位置",
         "level": "D"},

    "android.permission.ACCESS_SURFACE_FLINGER":
        {"description": "Android平台上底层的图形显示支持:一般用于游戏或照相机预览界面和底层模式的屏幕截图", "level": "N"},

    "android.permission.ACCESS_WIFI_STATE":
        {"description": "获取当前WiFi接入的状态以及WLAN热点的信息", "level": "N"},

    "android.permission.ACCOUNT_MANAGER":
        {"description": "获取账户验证信息:主要为GMail账户信息:只有系统级进程才能访问的权限", "level": "N"},

    "android.permission.ACTIVITY_RECOGNITION":
        {"description": "允许应用程序识别体力活动", "level": "D"},

    "android.permission.ADD_VOICEMAIL":
        {"description": "允许应用程序向系统中添加语音邮件", "level": "D"},

    "android.permission.ANSWER_PHONE_CALLS":
        {"description": "允许应用程序接听手机来电", "level": "D"},

    "android.permission.AUTHENTICATE_ACCOUNTS":
        {"description": "允许一个程序通过账户验证方式访问账户管理ACCOUNT_MANAGER相关信息", "level": "N"},

    "android.permission.BATTERY_STATS":
        {"description": "获取电池电量统计信息", "level": "N"},

    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        {
            "description": "必须是AccessibilityService所必需的，以确保只有系统可以绑定到它",
            "level": "signature"
        },

    "android.permission.BIND_APPWIDGET":
        {
            "description": "允许应用程序告诉AppWidget服务哪个应用程序可以访问AppWidget的数据。正常的用户流是，"
                           "用户选择一个AppWidget进入特定的主机，从而允许该主机应用程序访问来自AppWidget应用程序的私有数据。具有此权限的应用程序应遵守该合同:只有非常少的应用才用到此权限",
            "level": "N"},

    "android.permission.BIND_AUTOFILL_SERVICE":
        {"description": "自动填充服务，必须是AccessibilityService所必需的，以确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_CALL_REDIRECTION_SERVICE":
        {"description": "重定向服务", "level": "signature|privileged"},

    "android.permission.BIND_CARRIER_MESSAGING_CLIENT_SERVICE":
        {
            "description": "A subclass of CarrierMessagingClientService must be protected with this permission",
            "level": "signature"},

    "android.permission.BIND_CARRIER_SERVICES":
        {"description": "允许绑定到运营商应用程序中的服务的系统进程将具有此权限。运营商应用程序应使用此权限保护其仅允许系统绑定到的服务。",
         "level": "signature|privileged"},

    "android.permission.BIND_CHOOSER_TARGET_SERVICE":
        {"description": "必须由ChooserTargetService要求,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_CONDITION_PROVIDER_SERVICE":
        {"description": "必须由ConditionProviderService要求,确保只有系统可以绑定到它。", "level": "signature|privileged"},

    "android.permission.BIND_CONTROLS":
        {"description": "允许SystemUI请求第三方控件", "level": "N"},

    "android.permission.BIND_DEVICE_ADMIN":
        {"description": "请求系统管理员接收者receiver:只有系统才能使用", "level": "signature"},

    "android.permission.BIND_DREAM_SERVICE":
        {"description": "必须要求一个DreamService,确保只有系统可以绑定到它。", "level": "signature"},

    "android.permission.BIND_INCALL_SERVICE":
        {"description": "必须要求一个DreamService,确保只有系统可以绑定到它。", "level": "signature"},

    "android.permission.BIND_INPUT_METHOD ":
        {"description": "请求InputMethodService服务:只有系统才能使用", "level": "signature"},

    "android.permission.BIND_MIDI_DEVICE_SERVICE":
        {"description": "必须要求一个MidiDeviceService,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_NFC_SERVICE":
        {"description": "必须要求HostApduService或OffHostApduService确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
        {"description": "必须要求一个NotificationListenerService,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_PRINT_SERVICE":
        {"description": "必须由PrintService要求,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_QUICK_ACCESS_WALLET_SERVICE":
        {"description": "必须要求QuickAccessWalletService确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_QUICK_SETTINGS_TILE":
        {"description": "允许应用程序绑定到第三方快速设置磁贴", "level": "signature"},

    "android.permission.BIND_SCREENING_SERVICE":
        {"description": "必须由CallScreeningService要求,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_REMOTEVIEWS":
        {"description": "必须通过RemoteViewsService服务来请求:只有系统才能用", "level": "signature|privileged"},

    "android.permission.BIND_TELECOM_CONNECTION_SERVICE":
        {"description": "必须由ConnectionService要求,确保只有系统可以绑定到它", "level": "signature|privileged"},

    "android.permission.BIND_TEXT_SERVICE":
        {"description": "必须要求TextService(例如SpellCheckerService),以确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_TV_INPUT":
        {"description": "必须要求TvInputService确保只有系统可以绑定到它", "level": "signature|privileged"},

    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE":
        {"description": "必须需要一个链接VisualVoicemailService确保只有系统可以绑定到它", "level": "signature|privileged"},

    "android.permission.BIND_VOICE_INTERACTION":
        {"description": "必须由VoiceInteractionService要求,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_VPN_SERVICE":
        {"description": "必须由VpnService要求,确保只有系统可以绑定到它", "level": "signature|privileged"},

    "android.permission.BIND_VR_LISTENER_SERVICE":
        {"description": "必须要求一个VrListenerService,确保只有系统可以绑定到它", "level": "signature"},

    "android.permission.BIND_WALLPAPER":
        {"description": "必须通过WallpaperService服务来请求:只有系统才能用", "level": "signature|privileged"},

    "android.permission.BLUETOOTH":
        {"description": "允许程序连接配对过的蓝牙设备", "level": "N"},

    "android.permission.BLUETOOTH_ADMIN":
        {"description": "允许程序进行发现和配对新的蓝牙设备", "level": "N"},

    "android.permission.BLUETOOTH_PRIVILEGED":
        {"description": "允许应用程序对蓝牙设备没有用户交互,并允许或不允许电话簿访问或信息的访问", "level": "N"},

    "android.permission.BODY_SENSORS":
        {"description": "允许应用程序访问数据从用户使用的传感器,用于测量身体内部发生了什么,比如心率", "level": "D", "API": 20},

    "android.permission.BRICK":
        {"description": "能够禁用手机:非常危险:顾名思义就是让手机变成砖头", "level": "N"},

    "android.permission.BROADCAST_PACKAGE_REMOVED":
        {"description": "当一个应用在删除时触发一个广播", "level": "N"},

    "android.permission.BROADCAST_SMS":
        {"description": "当收到短信时触发一个广播", "level": "N"},

    "android.permission.BROADCAST_STICKY":
        {"description": "允允许应用程序广播的意图。这些广播的数据是由系统完成后,这样客户可以快速检索数据,而不必等待下一个广播", "level": "N"},

    "android.permission.BROADCAST_WAP_PUSH":
        {"description": "允许应用程序广播WAP推送回执通知", "level": "N"},

    "android.permission.CALL_COMPANION_APP":
        {"description": "允许实现InCallService API的应用程序有资格作为调用伴侣应用程序启用", "level": "N", "API": 29},

    "android.permission.CALL_PHONE":
        {"description": "允许应用程序启动电话呼叫，而无需通过拨号程序用户界面来确认呼叫", "level": "D", "API": 1},

    "android.permission.CALL_PRIVILEGED":
        {"description": "允许应用程序呼叫任何电话号码，包括紧急号码，而无需通过拨号程序用户界面来确认所拨打的电话", "level": "N", "API": 1},

    "android.permission.CAMERA":
        {"description": "允许访问摄像头进行拍照", "level": "D", "API": 1},

    "android.permission.CAPTURE_AUDIO_OUTPUT":
        {"description": "允许应用程序捕获音频输出", "level": "D", "API": 19},

    "android.permission.CHANGE_COMPONENT_ENABLED_STATE":
        {"description": "允许应用程序更改是否启用了应用程序组件（而不是它自己的组件）", "level": "N", "API": 1},

    "android.permission.CHANGE_CONFIGURATION":
        {"description": "允许当前应用改变配置:如定位",
         "level": "signature|privileged|development", "API": 1},

    "android.permission.CHANGE_NETWORK_STATE":
        {"description": "允许应用程序改变网络状态", "level": "N", "API": 1},

    "android.permission.CHANGE_WIFI_MULTICAST_STATE":
        {"description": "允许应用程序进入Wi-Fi多播模式", "level": "N", "API": 4},

    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS":
        {"description": "请求忽略电池优化", "level": "N", "API": 23},

    "android.permission.CHANGE_WIFI_STATE":
        {"description": "允许应用程序改变WiFi状态", "level": "N", "API": 1},
    "android.permission.REQUEST_INSTALL_PACKAGES":
        {"description": "允许一个应用程序请求安装包", "level": "signature", "API": 23},

    "android.permission.REQUEST_PASSWORD_COMPLEXITY":
        {"description": "允许应用程序请求屏幕锁的复杂性，并提示用户将屏幕锁更新到特定的复杂性级别", "level": "N", "API": 29},
    "android.permission.SEND_RESPOND_VIA_MESSAGE":
        {"description": "允许应用程序（电话）向其他应用程序发送请求，以处理传入呼叫期间通过消息响应操作", "level": "N", "API": 18},
    "com.android.alarm.permission.SET_ALARM":
        {"description": "允许应用程序广播为用户设置警报的意图", "level": "N", "API": 9},

    "android.permission.CLEAR_APP_CACHE":
        {"description": "清除应用缓存", "level": "N"},

    "android.permission.CLEAR_APP_USER_DATA":
        {"description": "清除应用的用户数据", "level": "N"},

    "android.permission.CWJ_GROUP":
        {"description": "允许CWJ账户组访问底层信息", "level": "N"},

    "android.permission.CELL_PHONE_MASTER_EX":
        {"description": "手机优化大师扩展权限", "level": "N"},

    "android.permission.CONTROL_LOCATION_UPDATES":
        {"description": "允许获得移动网络定位信息改变", "level": "N"},

    "android.permission.DELETE_CACHE_FILES":
        {"description": "允许应用删除缓存文件", "level": "N"},

    "android.permission.DELETE_PACKAGES":
        {"description": "允许程序删除应用", "level": "N"},

    "android.permission.DEVICE_POWER":
        {"description": "允许访问底层电源管理", "level": "N"},

    "android.permission.DIAGNOSTIC":
        {"description": "允许程序到RW到诊断资源", "level": "N"},

    "android.permission.DISABLE_KEYGUARD":
        {"description": "允许程序禁用键盘锁", "level": "N"},

    "android.permission.DUMP":
        {"description": "允许程序获取系统dump信息从系统服务", "level": "N"},

    "android.permission.EXPAND_STATUS_BAR":
        {"description": "允许程序扩展或收缩状态栏", "level": "N"},

    "android.permission.FACTORY_TEST":
        {"description": "允许程序运行工厂测试模式", "level": "N"},

    "android.permission.FLASHLIGHT":
        {"description": "允许访问闪光灯", "level": "N"},

    "android.permission.FORCE_BACK":
        {"description": "允许程序强制使用back后退按键:无论Activity是否在顶层", "level": "N"},

    "android.permission.GET_ACCOUNTS":
        {"description": "访问GMail账户列表", "level": "D"},

    "android.permission.GET_PACKAGE_SIZE":
        {"description": "获取应用的文件大小", "level": "N"},

    "android.permission.GET_TASKS":
        {"description": "允许程序获取当前或最近运行的应用", "level": "N"},

    "android.permission.GLOBAL_SEARCH":
        {"description": "允许程序使用全局搜索功能", "level": "N"},

    "android.permission.HARDWARE_TEST":
        {"description": "访问硬件辅助设备:用于硬件测试", "level": "N"},

    "android.permission.INJECT_EVENTS":
        {"description": "允许访问本程序的底层事件:获取按键、轨迹球的事件流", "level": "N"},

    "android.permission.INSTALL_LOCATION_PROVIDER":
        {"description": "安装定位提供", "level": "N"},

    "android.permission.INSTALL_PACKAGES":
        {"description": "允许程序安装应用", "level": "D"},

    "android.permission.INTERNAL_SYSTEM_WINDOW":
        {"description": "允许程序打开内部窗口:不对第三方应用程序开放此权限", "level": "N"},

    "android.permission.INTERNET":
        {"description": "访问网络连接:可能产生GPRS流量", "level": "N"},

    "android.permission.KILL_BACKGROUND_PROCESSES":
        {"description": "允许程序调用killBackgroundProcesses(String).方法结束后台进程", "level": "N"},

    "android.permission.MANAGE_ACCOUNTS":
        {"description": "允许程序管理AccountManager中的账户列表", "level": "N"},

    "android.permission.MANAGE_APP_TOKENS":
        {"description": "管理创建、摧毁、Z轴顺序:仅用于系统", "level": "N"},

    "android.permission.MTWEAK_USER":
        {"description": "允许mTweak用户访问高级系统权限", "level": "N"},

    "android.permission.MTWEAK_FORUM":
        {"description": "允许使用mTweak社区权限", "level": "N"},

    "android.permission.MASTER_CLEAR":
        {"description": "允许程序执行软格式化:删除系统配置信息", "level": "N"},

    "android.permission.MODIFY_AUDIO_SETTINGS":
        {"description": "修改声音设置信息", "level": "N"},

    "android.permission.MODIFY_PHONE_STATE":
        {"description": "修改电话状态:如飞行模式:但不包含替换系统拨号器界面", "level": "N"},

    "android.permission.MOUNT_FORMAT_FILESYSTEMS":
        {"description": "格式化可移动文件系统:比如格式化清空SD卡", "level": "D"},

    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS":
        {"description": "挂载、反挂载外部文件系统", "level": "D"},

    "android.permission.NFC":
        {"description": "允许程序执行NFC近距离通讯操作:用于移动支持", "level": "N"},

    "android.permission.PERSISTENT_ACTIVITY":
        {"description": "创建一个永久的Activity:该功能标记为将来将被移除", "level": "N"},

    "android.permission.PROCESS_OUTGOING_CALLS":
        {"description": "允许程序监视:修改或放弃播出电话", "level": "D"},

    "android.permission.READ_CALENDAR":
        {"description": "允许程序读取用户的日程信息", "level": "D"},

    "android.permission.READ_CONTACTS":
        {"description": "允许应用访问联系人通讯录信息", "level": "D"},

    "android.permission.READ_FRAME_BUFFER":
        {"description": "读取帧缓存用于屏幕截图", "level": "N"},

    "android.permission.READ_INPUT_STATE":
        {"description": "读取当前键的输入状态:仅用于系统", "level": "N"},

    "android.permission.READ_LOGS":
        {"description": "读取系统底层日志", "level": "N"},

    "android.permission.READ_PHONE_STATE":
        {"description": "访问电话状态", "level": "D"},

    "android.permission.READ_SMS":
        {"description": "读取短信内容", "level": "D"},

    "android.permission.READ_SYNC_SETTINGS":
        {"description": "读取同步设置:读取Google在线同步设置", "level": "N"},

    "android.permission.READ_SYNC_STATS":
        {"description": "读取同步状态:获得Google在线同步状态", "level": "N"},

    "android.permission.REBOOT":
        {"description": "允许程序重新启动设备", "level": "N"},

    "android.permission.RECEIVE_BOOT_COMPLETED":
        {"description": "允许程序开机自动运行", "level": "N"},

    "android.permission.RECEIVE_MMS":
        {"description": "允许应用程序接收彩信", "level": "D"},

    "android.permission.RECEIVE_SMS":
        {"description": "允许应用程序接收短信", "level": "D"},

    "android.permission.RECEIVE_WAP_PUSH":
        {"description": "接收WAP PUSH信息", "level": "D"},

    "android.permission.RECORD_AUDIO":
        {"description": "录制声音通过手机或耳机的麦克", "level": "D"},

    "android.permission.REORDER_TASKS":
        {"description": "允许应用程序将任务移动到前台和后台", "level": "N"},

    "android.permission.RESTART_PACKAGES":
        {"description": "结束任务通过restartPackage(String)方法:该方式将在外来放弃", "level": "D"},

    "android.permission.SEND_SMS":
        {"description": "允许一个应用程序发送SMS消息", "level": "D", "API": 1},

    "android.permission.SET_ACTIVITY_WATCHER":
        {"description": "设置Activity观察器一般用于monkey测试", "level": "N"},

    "android.permission.SET_ALWAYS_FINISH":
        {"description": "允许程序设置程序在后台是否总是退出", "level": "N", "API": 1},

    "android.permission.SET_ANIMATION_SCALE":
        {"description": "设置全局动画缩放", "level": "N", "API": 1},

    "android.permission.SET_DEBUG_APP":
        {"description": "设置调试程序:一般用于开发", "level": "N", "API": 1},

    "android.permission.SET_ORIENTATION":
        {"description": "设置屏幕方向为横屏或标准方式显示:不用于普通应用,允许低级别的设置屏幕的方向", "level": "N"},

    "android.permission.SET_PREFERRED_APPLICATIONS":
        {"description": "设置应用的参数:已不再工作具体查看addPackageToPreferred(String) 介绍,在API 15已弃用", "level": "N", "API": 1},

    "android.permission.SET_PROCESS_LIMIT":
        {"description": "允许应用程序设置可以运行的最大应用程序进程数（不需要）", "level": "N", "API": 1},

    "android.permission.SET_TIME":
        {"description": "允许应用程序直接设置系统时间", "level": "N", "API": 8},

    "android.permission.SET_TIME_ZONE":
        {"description": "允许应用程序设置系统时区(不供第三方应用程序使用)", "level": "N", "API": 1},

    "android.permission.SET_WALLPAPER":
        {"description": "允许应用程序设置桌面壁纸", "level": "N", "API": 1},

    "android.permission.SET_WALLPAPER_HINTS":
        {"description": "允许应用程序设置壁纸建议", "level": "N", "API": 1},

    "android.permission.SIGNAL_PERSISTENT_PROCESSES":
        {"description": "允许应用程序请求向所有持久进程发送信号(不供第三方应用程序使用)", "level": "N", "API": 1},

    "android.permission.SMS_FINANCIAL_TRANSACTIONS":
        {"description": "允许持有者启动应用程序的权限使用屏幕", "level": "signature|installer", "API": 29},

    "android.permission.ACCESS_GPS":
        {"description": "获取GPS定位和获取位置权限和位置信息", "level": "D"},

    "android.permission.START_VIEW_PERMISSION_USAGE":
        {"description": "允许持有者启动应用程序的权限使用屏幕", "level": "signature", "API": 29},

    "android.permission.STATUS_BAR":
        {"description": "允许程序打开、关闭、禁用状态栏", "level": "N", "API": 1},

    "android.permission.TRANSMIT_IR":
        {"description": "允许使用设备的红外发射器（如果可用）", "level": "N", "API": 19},

    "com.android.launcher.permission.UNINSTALL_SHORTCUT":
        {"description": "This permission is no longer supported", "level": "N", "API": 19},

    "android.permission.USE_FINGERPRINT":
        {"description": "允许应用程序使用硬件指纹,Deprecated in API level 28", "level": "N", "API": 23},

    "android.permission.SUBSCRIBED_FEEDS_READ":
        {"description": "允许应用访问内容提供者的签署认证", "level": "N"},

    "android.permission.SUBSCRIBED_FEEDS_WRITE":
        {"description": "写入或修改订阅内容的数据库", "level": "N"},

    "android.permission.SYSTEM_ALERT_WINDOW":
        {"description": "允许应用程序显示系统窗口,很少有应用程序应该使用此权限；这些窗口用于与用户进行系统级交互",
         "level": "signature|preinstalled|appop|pre23|development", "API": 1},

    "android.permission.UPDATE_DEVICE_STATS":
        {"description": "允许应用程序更新设备统计信息(不供第三方应用程序使用)", "level": "N", "API": 3},

    "android.permission.USE_BIOMETRIC":
        {"description": "允许应用程序使用设备支持的生物识别模式", "level": "N", "API": 28},

    "android.permission.USE_FULL_SCREEN_INTENT":
        {"description": "应用程序目标需要Android.Q希望使用全屏通知意图(通知)", "level": "N", "API": 29},

    "android.permission.USE_CREDENTIALS":
        {"description": "允许程序请求验证从AccountManager", "level": "N"},

    "android.permission.USE_SIP":
        {"description": "允许应用程序使用SIP视频服务", "level": "D", "API": 9},

    "android.permission.VIBRATE":
        {"description": "允许振动", "level": "N", "API": 1},

    "android.permission.WAKE_LOCK":
        {"description": "允许应用程序使用(PowerManager )屏幕保持唤醒,不锁屏", "level": "N", "API": 1},

    "android.permission.WRITE_APN_SETTINGS":
        {"description": "允许应用程序写入apn设置并读取现有apn设置（如用户和密码）的敏感字段", "level": "N", "API": 1},

    "android.permission.WRITE_CALENDAR":
        {"description": "允许应用程序写入用户的日历数据", "level": "D", "API": 1},

    "android.permission.WRITE_CALL_LOG":
        {"description": "允许应用程序写入（但不读取）用户的呼叫日志数据", "level": "D", "API": 16},

    "android.permission.WRITE_CONTACTS":
        {"description": "允许应用程序写入用户的联系人数据", "level": "D", "API": 1},

    "android.permission.WRITE_EXTERNAL_STORAGE":
        {"description": "允许程序写入外部存储:如SD卡上写文件", "level": "D", "API": 4},

    "android.permission.READ_EXTERNAL_STORAGE":
        {"description": "允许程序读外部存储:如SD卡上读文件", "level": "D", "API": 4},

    "android.permission.WRITE_GSERVICES":
        {"description": "允许应用程序修改Google Map服务数据(不供第三方应用程序使用)", "level": "N", "API": 1},

    "android.permission.WRITE_SECURE_SETTINGS":
        {"description": "允许应用程序读取或写入安全系统设置(不供第三方应用程序使用)", "level": "D", "API": 3},

    "android.permission.WRITE_SETTINGS":
        {"description": "允许应用程序读取或写入系统设置", "level": "signature|preinstalled|appop|pre23", "API": 1},

    "android.permission.WRITE_SMS":
        {"description": "允许编写短信", "level": "N"},

    "android.permission.WRITE_SYNC_SETTINGS":
        {"description": "允许应用程序写入同步设置", "level": "N", "API": 1},

    "com.android.voicemail.permission.WRITE_VOICEMAIL":
        {"description": "允许应用程序修改和删除系统中现有的语音邮件", "level": "N", "API": 21},

    "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS":
        {"description": "写入浏览器历史记录或收藏夹，但不可读取", "level": "N", "API": 21},

    "android.permission.READ_CALL_LOG":
        {"description": "读取通话记录", "level": "D"},

}

normalPermissions = {
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.ACCESS_WIMAX_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BROADCAST_STICKY",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.CHANGE_WIMAX_STATE",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FLASHLIGHT",
    "android.permission.GET_ACCOUNTS",
    "android.permission.GET_PACKAGE_SIZE",
    "android.permission.INTERNET",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.NFC",
    "android.permission.READ_SYNC_SETTINGS",
    "android.permission.READ_SYNC_STATS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REORDER_TASKS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SET_TIME_ZONE",
    "android.permission.SET_WALLPAPER",
    "android.permission.SET_WALLPAPER_HINTS",
    "android.permission.SUBSCRIBED_FEEDS_READ",
    "android.permission.TRANSMIT_IR",
    "android.permission.USE_FINGERPRINT",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.WRITE_SYNC_SETTINGS",
    "com.android.alarm.permission.SET_ALARM",
    "com.android.launcher.permission.INSTALL_SHORTCUT",
    "com.android.launcher.permission.UNINSTALL_SHORTCUT",
}

dangerousPermissions = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}
