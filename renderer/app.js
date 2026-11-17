'use strict';

const $ = (id) => document.getElementById(id);

const DICT = {
  ar: {
    secureTunnel: 'نفق آمن',
    selectedServer: 'الخادم المحدد',
    manage: 'إدارة',
    server: 'الخادم',
    publicBadge: 'عام',
    badgePrivate: 'خاص',
    protocol: 'البروتوكول',
    exitIp: 'عنوان الخروج',
    duration: 'المدة',
    pingMeasured: 'بينغ (قياس)',
    downloadMeasured: 'تنزيل (قياس)',
    upload: 'رفع (غير مقاس)',
    downloaded: 'تنزيل (حي)',
    uploaded: 'رفع (حي)',
    statistics: 'الإحصائيات',
    measuredDownload: 'سرعة التنزيل المقاسة',
    probe: 'فحص النفق',
    ipv6: 'IPv6',
    ipv6Blocked: 'مضبوط على الحجب',
    liveNote: 'العدّادات اللحظية غير متاحة في هذه النسخة؛ تُعرض نتيجة القياس مرة واحدة.',
    servers: 'الخوادم',
    measure: 'قياس',
    refresh: 'تحديث',
    searchPlaceholder: 'ابحث عن بلد أو خادم',
    settings: 'الإعدادات',
    credentials: 'بيانات دخول الخوادم العامة',
    username: 'اسم المستخدم',
    password: 'كلمة المرور',
    remember: 'حفظ مشفراً على هذا الجهاز',
    save: 'حفظ',
    privateProfile: 'الملف الخاص',
    importProfile: 'استيراد ملف',
    remove: 'إزالة',
    encryptedNote: 'يُخزَّن الملف مشفراً بمفتاح Windows، ولا يُحفظ نصاً صريحاً.',
    engine: 'محرك OpenVPN',
    chooseEngine: 'اختيار المحرك',
    engineStrictNote: 'ارفض الاتصال إذا كان المحرك غير موقّع أو موقّعاً من جهة غير OpenVPN Inc.',
    certTitle: 'شهادة الخادم',
    certNote: 'تُثبَّت بصمة SHA-256 لشهادة الخادم الفعلية عند أول اتصال ناجح، وأي تغيّر لاحق يُصنَّف خطراً. لا تُعد التثبيت إلا بعد التأكد أن التغيير صادر عن مشغّل خادمك.',
    repinCert: 'إعادة تثبيت الشهادة الحالية',
    repinDone: 'أُعيد تثبيت الشهادة الحالية',
    repinNone: 'لا توجد شهادة مثبتة بعد',
    disclosureTitle: 'شاشة الإفصاح',
    showAgain: 'إظهارها مجدداً',
    about: 'حول',
    updates: 'التحديثات',
    releaseFeed: 'رابط ملف الإصدار HTTPS',
    checkUpdates: 'فحص التحديثات',
    updateNotConfigured: 'لم يُضبط رابط تحديث.',
    updateChecking: 'جارٍ فحص التحديثات…',
    updateCurrent: 'أنت تستخدم أحدث إصدار ({version}).',
    updateAvailable: 'يتوفر إصدار {version}. نزّله من جهة الإصدار الموثوقة بعد التحقق من التوقيع والهاش.',
    home: 'الرئيسية',
    disclosureHeading: 'قبل الاتصال',
    disclosureBody:
      'ينشئ AI VPN نفقاً مشفراً إلى خادمك الخاص. قد يعالج مشغّل الخادم والمواقع بيانات الاتصال وحركة المرور. لا يبيع التطبيق الترافيك ولا يستخدم تتبعاً إعلانياً. يفحص التطبيق عنوان الخروج والسرعة محلياً عبر Cloudflare وapi.ipify.org.',
    cancel: 'إلغاء',
    accept: 'أفهم وأوافق',

    status_DISCONNECTED: 'غير متصل',
    status_CONNECTING: 'جارٍ الاتصال',
    status_CONNECTED: 'متصل',
    status_DISCONNECTING: 'جارٍ الفصل',
    status_FAILED: 'فشل الاتصال',
    subDisconnected: 'اضغط للاتصال',
    subConnecting: 'جارٍ إنشاء النفق…',
    subReconnecting: 'إعادة الاتصال…',
    subConnected: 'النفق مشفّر ومفعّل',
    subDisconnecting: 'جارٍ إغلاق النفق…',

    notConnected: 'لم يتم الاتصال',
    privateLabel: 'الملف الخاص',
    privateMeta: 'خادم OpenVPN خاص بك',
    notMeasured: 'لم يُقس',
    viaSource: 'عبر {source}',
    connect: 'اتصال',
    disconnect: 'فصل',

    serversEmpty: 'لا توجد خوادم بعد — اضغط تحديث.',
    serversCount: '{n} خادم · آخر تحديث {when}',
    searchEmpty: 'لا نتائج مطابقة لهذا البحث.',
    noSession: 'لا توجد جلسة نشطة',
    probeOk: 'ناجح',
    probeFail: 'تعذّر الفحص — قد يكون النفق محجوباً',
    probeNone: '—',
    engineBanner: 'محرك OpenVPN غير مثبت. ثبّت OpenVPN 2.6 أو اختر openvpn.exe من الإعدادات — اضغط هنا.',
    engineMissingShort: 'محرك OpenVPN غير موجود',
    credsNone: 'تشفير النظام غير متاح؛ لن تُحفظ الأسرار على هذا الجهاز.',
    credsMemory: 'تبقى في الذاكرة لهذه الجلسة فقط.',
    credsSaved: 'محفوظة مشفرة بمفتاح Windows.',
    profileNone: 'لا يوجد ملف خاص مستورد.',
    profileExpires: 'تنتهي شهادة الملف في {date}.',
    profileExpiryUnknown: 'تعذّر قراءة تاريخ انتهاء شهادة الملف.',
    engineNone: 'غير موجود. ثبّت OpenVPN 2.6 أو اختر openvpn.exe.',
    disclosureOn: 'مقبولة — لن يسأل التطبيق مجدداً.',
    disclosureOff: 'ستظهر عند محاولة الاتصال القادمة.',
    aboutText: 'الإصدار {version} · المشروع MIT · يستخدم OpenVPN 2.6 (GPLv2) وملف الاتصال الخاص بك.',
    refreshing: 'جارٍ التحديث…',
    refreshed: 'حُدّثت قائمة الخوادم',
    refreshFailed: 'تعذّر الوصول إلى الدليل',
    measuring: 'جارٍ القياس…',
    measuredDone: 'اكتمل قياس الوصول',
    measureFailed: 'فشل القياس',
    saved: 'حُفظ',
    profileImported: 'استُورد الملف',
    profileRemoved: 'أُزيل الملف',
    profileImportFailed: 'رُفض الملف',
    noServers: 'لا يوجد خادم محدد بعد',
    privateMissing: 'استورد ملفاً خاصاً أولاً',
    needRefresh: 'انتهت صلاحية القائمة — يجري التحديث',
    untitled: '—',

    guardTitle: 'حالة الحماية',
    guardAlertCritical: 'فحص الحماية وجد خطراً في النفق — اضغط لعرض التفاصيل.',
    guardAlertWarn: 'فحص الحماية وجد تحذيراً — اضغط لعرض التفاصيل.',
    guardCheck: 'فحص الآن',
    guardChecking: 'جارٍ الفحص…',
    guardNote: 'الفحوص محلية وقابلة للتحقق فقط؛ لا يمكن إثبات سلامة مشغّل خادم.',
    guardAt: 'آخر فحص {time}',
    guardNever: 'لم يُفحص بعد',
    guardIdleHint: 'يبدأ الفحص تلقائياً بعد الاتصال.',
    killSwitchNote: 'حظر الإنترنت خارج النفق أثناء الاتصال، والتحقق منه في فحص الحماية.',
    killSwitchStrictNote: 'الوضع الصارم: إن انهار التطبيق يبقى الحظر قائماً حتى تستعيد الشبكة يدوياً.',
    killSwitchLockedNote: 'الشبكة مقفلة من جلسة سابقة. استعد الشبكة الآن.',
    restoreNetwork: 'استعادة الشبكة',
    restoreDone: 'استُعيدت الشبكة',
    restoreCancelled: 'أُلغي طلب الصلاحيات',
    check_session: 'الجلسة',
    check_tunnel: 'النفق',
    check_route: 'المسار',
    check_dns: 'DNS',
    check_ipv6: 'IPv6',
    check_firewall: 'Kill Switch',
    check_crypto: 'التشفير',
    check_cert: 'الشهادة',
    check_engine: 'المحرّك',
    check_residual: 'ما بعد الفصل',
    level_ok: 'سليم',
    level_warn: 'تحذير',
    level_critical: 'خطر',
    level_unknown: 'غير معروف',
    level_idle: 'غير متصل',
    guard_idle: 'لا جلسة نشطة — لا شيء لفحصه.',
    guard_tunnelOk: '{ip} على {iface}',
    guard_tunnelNoIface: '{ip} غير موجود على أي محوّل',
    guard_tunnelNotInit: 'السجل بلا Initialization Sequence Completed',
    guard_routeOk: '{routes}',
    guard_routeMissing: 'لا مسار 0.0.0.0/1 أو 128.0.0.0/1 عبر {gw}',
    guard_routePartial: 'مسار ناقص: {missing} غير موجود عبر {gw}',
    guard_routeUnknown: 'بوابة النفق غير مذكورة في السجل',
    guard_dnsOk: '{count} محوّل يستخدم DNS النفق ({servers})',
    guard_dnsMissing: 'لا محوّل يستخدم DNS المدفوع ({servers})',
    guard_dnsOutside: 'DNS النفق مسجّل على محوّل آخر: {iface} ({servers})',
    guard_ipv6Ok: 'لا مسار IPv6 افتراضي خارج النفق',
    guard_ipv6Unknown: 'تعذّرت قراءة مسارات IPv6 الافتراضية',
    guard_ipv6Outside: 'مسار IPv6 افتراضي عبر {iface} — احتمال تسريب',
    guard_fwOk: 'جدار الحماية يحظر الخروج: {profiles} ملفات تعريف و{rules} قاعدتي سماح',
    guard_fwOpen: 'Kill Switch غير مفعّل فعلياً: {open}',
    guard_fwNoRules: 'لا قواعد سماح بأسماء Kill Switch — قد يتعطل النفق',
    guard_fwUnknown: 'تعذّر قراءة حالة جدار الحماية',
    guard_cryptoOk: '{tls} · {cipher}/{auth}',
    guard_cryptoPartial: 'بيانات ناقصة في السجل: {tls} · {cipher}/{auth}',
    guard_cryptoWeak: 'إعدادات قديمة: {reasons}',
    guard_certPinned: 'أول بصمة SHA-256 سُجّلت ({fp}) · {first}',
    guard_certMatch: 'مطابقة للبصمة المسجّلة ({fp}) · {first}',
    guard_certChanged: 'تغيّرت بصمة شهادة الخادم ({oldFp} ← {nowFp}) عن سجل {date}. إن لم تعرف سبب التغيير فافصل الاتصال الآن؛ وإن كان شرعياً فأعد التثبيت من الإعدادات.',
    guard_certNone: 'لا سلسلة تحقق في السجل',
    guard_certNoFingerprint: 'لم تُقرأ بصمة SHA-256 لهذه الجلسة؛ سلسلة التحقق وحدها ليست تثبيتاً ({first}). أعد الاتصال لتسجيل البصمة.',
    guard_engineValid: '{signer}',
    guard_engineWarn: 'التوقيع {status} · {signer}',
    guard_engineForeign: 'موقّع من جهة غير OpenVPN Inc.: {signer}',
    guard_engineUnknown: 'تعذّر قراءة توقيع المحرّك',
    guard_residualRoute: 'مسارات بقيت عبر بوابة النفق بعد الفصل: {routes}',
    guard_residualDns: 'خوادم DNS الخاصة بالنفق ما زالت مسجّلة على {iface} ({servers})',
    guard_residualAddress: 'عنوان النفق {ip} ما زال موجوداً على المحوّل بعد الفصل',
    intelTitle: 'آخر التحديثات الأمنية',
    refreshIntel: 'تحديث',
    intelWhen: 'آخر تحديث {time} · {n} عنصراً',
    intelEmpty: 'لا عناصر بعد — يُحدَّث تلقائياً كل 24 ساعة.',
    intelFailed: 'تعذّر التحديث — تُعرض آخر نسخة محفوظة.',
    intelMore: '+{n} عنصراً إضافياً',
    intelKev: 'استغلال معروف',

    err_ENGINE_MISSING: 'محرك OpenVPN غير مثبت',
    err_ENGINE_UNTRUSTED: 'رفضت الحماية تشغيل المحرك: توقيعه غير صالح أو من جهة غير OpenVPN Inc.',
    err_ENGINE_DIR_UNSAFE: 'مجلد المحرك قابل للكتابة لحسابك، ما يسمح بزرع مكتبة بجانبه. ثبّت OpenVPN في مجلد محمي.',
    err_ENGINE_PICK_REQUIRED: 'اختر المحرك المخصص من الإعدادات في هذه الجلسة قبل الاتصال (يتطلب إيقاف الفحص الصارم).',
    err_KILLSWITCH_LOCKED: 'شبكة الجهاز مقفلة من جلسة سابقة؛ استعد الشبكة أولاً.',
    err_KILLSWITCH_TARGET_INVALID: 'ملف الخادم لا يحدد عنوان IPv4 وبروتوكولاً صريحين، فلا يمكن تفعيل Kill Switch قبل الاتصال.',
    err_KILLSWITCH_PROTO_INVALID: 'ملف الخادم يفرض IPv6 (udp6 أو tcp6) وقاعدة Kill Switch الحالية تدعم IPv4 فقط. غيّر البروتوكول إلى udp أو tcp-client.',
    err_KILLSWITCH_RECOVERY_MISSING: 'ملف استرداد Kill Switch غير موجود.',
    err_KILLSWITCH_RESTORE_FAILED: 'تعذّرت استعادة الشبكة.',
    err_KILLSWITCH_ELEVATION_CANCELLED: 'أُلغي طلب صلاحية استعادة الشبكة.',
    err_KILLSWITCH_NOT_READY: 'لم يؤكّد Kill Switch تطبيق قواعد الحجب وقراءتها قبل بدء النفق، فأُلغي الاتصال. تحقّق من صلاحية المسؤول وجدار الحماية ثم أعد المحاولة.',
    err_ELEVATION_CANCELLED: 'أُلغيت صلاحية المسؤول',
    err_TAMPERED: 'تغيّرت إعدادات التشغيل قبل منح الصلاحية؛ أُلغي التشغيل ولم يُفتح النفق. أعد المحاولة.',
    err_LAUNCH_FAILED: 'تعذّر تشغيل المحرك',
    err_ENGINE_STOP_FAILED: 'تعذّر التأكد من إيقاف المحرك المرتفع، وقد يبقى النفق قائماً. شغّل التطبيق كمسؤول ثم افصل، أو أعد تشغيل الجهاز.',
    err_SUPERVISOR_START_TIMEOUT: 'لم يؤكّد مشرف المحرك المرتفع بدء التشغيل في الوقت المحدد، فلا يُدّعى أن النفق فُتح. أعد المحاولة.',
    err_SESSION_BUSY: 'توجد جلسة قائمة بالفعل',
    err_NO_PRIVATE_PROFILE: 'لا يوجد ملف خاص',
    err_PRIVATE_ONLY: 'هذه النسخة تتصل بالملف الخاص فقط',
    err_SERVER_GONE: 'الخادم لم يعد في القائمة — حدّث القائمة',
    err_ENCRYPTION_UNAVAILABLE: 'تشفير النظام غير متاح',
    err_PROFILE_TOO_LARGE: 'الملف أكبر من الحد المسموح',
    err_PROFILE_INVALID: 'الملف ليس إعداد OpenVPN صالحاً',
    err_ENGINE_TIMEOUT: 'انتهت مهلة الاتصال',
    err_ENGINE_FAILED: 'فشل تشغيل النفق',
    err_MANAGEMENT_TIMEOUT: 'لم يستجب المحرك',
    err_STOPPED: 'أُوقف الاتصال',
    err_certpin: 'بصمة شهادة الخادم تغيّرت عن البصمة المثبتة، ولم يُفتح النفق. راجع سبب التغيير ثم أعد تثبيت الشهادة من الإعدادات.',
    err_certUnavailable: 'تعذّر التحقق من شهادة الخادم قبل فتح النفق، ولم تكن هناك بصمة محفوظة لهذا الخادم. أعد المحاولة.',
    err_auth: 'رُفضت بيانات الدخول',
    err_tls: 'فشل تبادل الشهادات (TLS)',
    err_driver: 'تعذّر فتح محول الشبكة — ثبّت TAP/Wintun',
    err_config: 'خطأ في إعدادات النفق',
    err_route: 'تعذّرت إضافة مسار الشبكة',
    err_engineexit: 'أُغلق المحرك فجأة',
    err_UPDATE_URL_INVALID: 'رابط التحديث يجب أن يكون HTTPS صالحاً',
    err_UPDATE_URL_MISSING: 'أدخل رابط ملف الإصدار أولاً',
    err_UPDATE_HTTP: 'تعذّر جلب ملف الإصدار',
    err_UPDATE_TIMEOUT: 'انتهت مهلة فحص التحديث',
    err_UPDATE_TOO_LARGE: 'ملف الإصدار كبير بشكل غير مقبول',
    err_UPDATE_INVALID: 'ملف الإصدار غير صالح',
    err_UPDATE_SIGNATURE: 'توقيع ملف الإصدار غير صالح أو غائب؛ رُفض التحديث.',
    err_UPDATE_FAILED: 'فشل فحص التحديث',
    err_unknown: 'فشل الاتصال لسبب غير معروف'
  },
  en: {
    secureTunnel: 'Secure tunnel',
    selectedServer: 'Selected server',
    manage: 'Manage',
    server: 'Server',
    publicBadge: 'Public',
    badgePrivate: 'Private',
    protocol: 'Protocol',
    exitIp: 'Exit IP',
    duration: 'Duration',
    pingMeasured: 'Ping (measured)',
    downloadMeasured: 'Download (measured)',
    upload: 'Upload (not measured)',
    downloaded: 'Downloaded (live)',
    uploaded: 'Uploaded (live)',
    statistics: 'Statistics',
    measuredDownload: 'Measured download speed',
    probe: 'Tunnel probe',
    ipv6: 'IPv6',
    ipv6Blocked: 'Configured to block',
    liveNote: 'Live counters are not available in this build; the measured result is shown once.',
    servers: 'Servers',
    measure: 'Measure',
    refresh: 'Refresh',
    searchPlaceholder: 'Search a country or server',
    settings: 'Settings',
    credentials: 'Public server sign-in',
    username: 'Username',
    password: 'Password',
    remember: 'Save encrypted on this device',
    save: 'Save',
    privateProfile: 'Private profile',
    importProfile: 'Import file',
    remove: 'Remove',
    encryptedNote: 'The profile is stored encrypted with the Windows key; no plaintext copy is written.',
    engine: 'OpenVPN engine',
    chooseEngine: 'Choose engine',
    engineStrictNote: 'Refuse to connect when the engine is unsigned or not signed by OpenVPN Inc.',
    certTitle: 'Server certificate',
    certNote: 'The SHA-256 fingerprint of the actual server certificate is pinned on the first successful connection, and any later change is critical. Only re-pin after confirming the change came from your server operator.',
    repinCert: 'Re-pin the current certificate',
    repinDone: 'The current certificate was pinned',
    repinNone: 'No certificate is pinned yet',
    disclosureTitle: 'Disclosure screen',
    showAgain: 'Show it again',
    about: 'About',
    updates: 'Updates',
    releaseFeed: 'HTTPS release manifest URL',
    checkUpdates: 'Check for updates',
    updateNotConfigured: 'No update feed is configured.',
    updateChecking: 'Checking for updates…',
    updateCurrent: 'You are using the latest version ({version}).',
    updateAvailable: 'Version {version} is available. Download it from the trusted release source after verifying signature and checksum.',
    home: 'Home',
    disclosureHeading: 'Before you connect',
    disclosureBody:
      'AI VPN creates an encrypted tunnel to your private server. The server operator and the websites you visit may process connection data and traffic. The app does not sell traffic or use ad tracking. It checks the exit IP and speed locally through Cloudflare and api.ipify.org.',
    cancel: 'Cancel',
    accept: 'I understand and agree',

    status_DISCONNECTED: 'Disconnected',
    status_CONNECTING: 'Connecting',
    status_CONNECTED: 'Connected',
    status_DISCONNECTING: 'Disconnecting',
    status_FAILED: 'Connection failed',
    subDisconnected: 'Press to connect',
    subConnecting: 'Building the tunnel…',
    subReconnecting: 'Reconnecting…',
    subConnected: 'Tunnel is encrypted and active',
    subDisconnecting: 'Closing the tunnel…',

    notConnected: 'Not connected',
    privateLabel: 'Private profile',
    privateMeta: 'Your own OpenVPN server',
    notMeasured: 'Not measured',
    viaSource: 'via {source}',
    connect: 'Connect',
    disconnect: 'Disconnect',

    serversEmpty: 'No servers yet — press Refresh.',
    serversCount: '{n} servers · updated {when}',
    searchEmpty: 'Nothing matches this search.',
    noSession: 'No active session',
    probeOk: 'Reachable',
    probeFail: 'Probe failed — the tunnel may be blocked',
    probeNone: '—',
    engineBanner: 'OpenVPN is not installed. Install OpenVPN 2.6 or choose openvpn.exe in Settings — click here.',
    engineMissingShort: 'OpenVPN engine not found',
    credsNone: 'System encryption is unavailable; secrets will not be stored on this device.',
    credsMemory: 'Kept in memory for this session only.',
    credsSaved: 'Saved encrypted with the Windows key.',
    profileNone: 'No private profile imported.',
    profileExpires: 'The profile certificate expires on {date}.',
    profileExpiryUnknown: 'The profile certificate expiry could not be read.',
    engineNone: 'Not found. Install OpenVPN 2.6 or pick openvpn.exe.',
    disclosureOn: 'Accepted — the app will not ask again.',
    disclosureOff: 'It will appear on the next connection attempt.',
    aboutText: 'Version {version} · MIT licensed · uses OpenVPN 2.6 (GPLv2) and your private connection profile.',
    refreshing: 'Refreshing…',
    refreshed: 'Server list updated',
    refreshFailed: 'Could not reach the directory',
    measuring: 'Measuring…',
    measuredDone: 'Reachability measured',
    measureFailed: 'Measurement failed',
    saved: 'Saved',
    profileImported: 'Profile imported',
    profileRemoved: 'Profile removed',
    profileImportFailed: 'Profile rejected',
    noServers: 'No server selected yet',
    privateMissing: 'Import a private profile first',
    needRefresh: 'Server list expired — refreshing',
    untitled: '—',

    guardTitle: 'Protection status',
    guardAlertCritical: 'The protection check found a critical issue in the tunnel — click for details.',
    guardAlertWarn: 'The protection check found a warning — click for details.',
    guardCheck: 'Check now',
    guardChecking: 'Checking…',
    guardNote: 'Checks are local and verifiable only; a server operator cannot be proven safe.',
    guardAt: 'Last check {time}',
    guardNever: 'Not checked yet',
    guardIdleHint: 'The check starts automatically once connected.',
    killSwitchNote: 'Block traffic outside the tunnel while connected; the protection check verifies it.',
    killSwitchStrictNote: 'Strict mode: if the app crashes, the block stays until you restore the network manually.',
    killSwitchLockedNote: 'The network is locked from a previous session. Restore it now.',
    restoreNetwork: 'Restore network',
    restoreDone: 'Network restored',
    restoreCancelled: 'Elevation was cancelled',
    check_session: 'Session',
    check_tunnel: 'Tunnel',
    check_route: 'Route',
    check_dns: 'DNS',
    check_ipv6: 'IPv6',
    check_firewall: 'Kill switch',
    check_crypto: 'Crypto',
    check_cert: 'Certificate',
    check_engine: 'Engine',
    check_residual: 'After disconnect',
    level_ok: 'OK',
    level_warn: 'Warning',
    level_critical: 'Critical',
    level_unknown: 'Unknown',
    level_idle: 'Disconnected',
    guard_idle: 'No active session — nothing to check.',
    guard_tunnelOk: '{ip} on {iface}',
    guard_tunnelNoIface: '{ip} is not present on any adapter',
    guard_tunnelNotInit: 'The log has no Initialization Sequence Completed',
    guard_routeOk: '{routes}',
    guard_routeMissing: 'No 0.0.0.0/1 or 128.0.0.0/1 route via {gw}',
    guard_routePartial: 'Split route missing: {missing} is not routed via {gw}',
    guard_routeUnknown: 'The tunnel gateway is not in the log',
    guard_dnsOk: '{count} adapter(s) use the tunnel DNS ({servers})',
    guard_dnsMissing: 'No adapter uses the pushed DNS ({servers})',
    guard_dnsOutside: 'Tunnel DNS is set on another adapter: {iface} ({servers})',
    guard_ipv6Ok: 'No IPv6 default route outside the tunnel',
    guard_ipv6Unknown: 'Could not read IPv6 default routes',
    guard_ipv6Outside: 'IPv6 default route via {iface} — possible leak',
    guard_fwOk: 'Firewall blocks outbound: {profiles} profiles and {rules} allow rules',
    guard_fwOpen: 'Kill switch is not actually enforced: {open}',
    guard_fwNoRules: 'No Kill Switch allow rules found — the tunnel may stall',
    guard_fwUnknown: 'The firewall state could not be read',
    guard_cryptoOk: '{tls} · {cipher}/{auth}',
    guard_cryptoPartial: 'Incomplete log facts: {tls} · {cipher}/{auth}',
    guard_cryptoWeak: 'Legacy settings: {reasons}',
    guard_certPinned: 'First SHA-256 fingerprint recorded ({fp}) · {first}',
    guard_certMatch: 'Matches the recorded fingerprint ({fp}) · {first}',
    guard_certChanged: 'The server certificate fingerprint changed ({oldFp} → {nowFp}) since the {date} record. If you do not recognise the change, disconnect now; if it is legitimate, re-pin it from Settings.',
    guard_certNone: 'No verification chain in the log',
    guard_certNoFingerprint: 'No SHA-256 fingerprint was read this session; a chain string alone is not a pin ({first}). Reconnect to record the fingerprint.',
    guard_engineValid: '{signer}',
    guard_engineWarn: 'Signature {status} · {signer}',
    guard_engineForeign: 'Signed by a non-OpenVPN publisher: {signer}',
    guard_engineUnknown: 'The engine signature could not be read',
    guard_residualRoute: 'Routes still point at the tunnel gateway after disconnect: {routes}',
    guard_residualDns: 'Tunnel DNS servers are still set on {iface} ({servers})',
    guard_residualAddress: 'The tunnel address {ip} is still on an adapter after disconnect',
    intelTitle: 'Latest security updates',
    refreshIntel: 'Refresh',
    intelWhen: 'Updated {time} · {n} items',
    intelEmpty: 'Nothing yet — it refreshes automatically every 24 hours.',
    intelFailed: 'Refresh failed — showing the last saved copy.',
    intelMore: '+{n} more items',
    intelKev: 'Known exploited',

    err_ENGINE_MISSING: 'OpenVPN engine is not installed',
    err_ENGINE_UNTRUSTED: 'Protection refused to run the engine: its signature is invalid or not from OpenVPN Inc.',
    err_ENGINE_DIR_UNSAFE: 'Your account can write to the engine folder, so a library could be planted next to it. Install OpenVPN in a protected folder.',
    err_ENGINE_PICK_REQUIRED: 'Pick the custom engine from Settings in this session before connecting (turn off strict checking first).',
    err_KILLSWITCH_LOCKED: 'The device network is locked from a previous session; restore it first.',
    err_KILLSWITCH_TARGET_INVALID: 'The profile has no explicit IPv4 address and protocol, so the kill switch cannot be armed before connecting.',
    err_KILLSWITCH_PROTO_INVALID: 'The profile forces IPv6 (udp6 or tcp6), but the kill switch rule covers IPv4 only. Change the protocol to udp or tcp-client.',
    err_KILLSWITCH_RECOVERY_MISSING: 'The kill switch recovery file is missing.',
    err_KILLSWITCH_RESTORE_FAILED: 'The network could not be restored.',
    err_KILLSWITCH_ELEVATION_CANCELLED: 'The network restore elevation was cancelled.',
    err_KILLSWITCH_NOT_READY: 'The kill switch did not confirm that its block rules were applied and read back before the tunnel started, so the connection was aborted. Check administrator approval and the firewall, then try again.',
    err_ELEVATION_CANCELLED: 'Administrator permission was cancelled',
    err_TAMPERED: 'The launch settings changed before elevation; nothing was started and no tunnel opened. Try again.',
    err_LAUNCH_FAILED: 'Could not launch the engine',
    err_ENGINE_STOP_FAILED: 'Could not confirm that the elevated engine stopped; the tunnel may still be up. Run the app as administrator and disconnect, or restart the machine.',
    err_SUPERVISOR_START_TIMEOUT: 'The elevated engine supervisor did not confirm startup in time, so the tunnel is not reported as open. Try again.',
    err_SESSION_BUSY: 'A session is already running',
    err_NO_PRIVATE_PROFILE: 'No private profile',
    err_PRIVATE_ONLY: 'This build connects to the private profile only',
    err_SERVER_GONE: 'That server left the list — refresh it',
    err_ENCRYPTION_UNAVAILABLE: 'System encryption is unavailable',
    err_PROFILE_TOO_LARGE: 'The file exceeds the size limit',
    err_PROFILE_INVALID: 'Not a valid OpenVPN profile',
    err_ENGINE_TIMEOUT: 'Connection timed out',
    err_ENGINE_FAILED: 'The tunnel failed to start',
    err_MANAGEMENT_TIMEOUT: 'The engine did not respond',
    err_STOPPED: 'Connection was stopped',
    err_certpin: 'The server certificate fingerprint changed since it was pinned, so the tunnel was not opened. Confirm the change, then re-pin from Settings.',
    err_certUnavailable: 'The server certificate could not be verified before the tunnel opened, and no pin was stored for this server. Try again.',
    err_auth: 'Credentials were rejected',
    err_tls: 'TLS handshake failed',
    err_driver: 'Could not open the network adapter — install TAP/Wintun',
    err_config: 'Invalid tunnel configuration',
    err_route: 'Could not add the network route',
    err_engineexit: 'The engine exited unexpectedly',
    err_UPDATE_URL_INVALID: 'The update URL must be valid HTTPS',
    err_UPDATE_URL_MISSING: 'Enter a release manifest URL first',
    err_UPDATE_HTTP: 'Could not fetch the release manifest',
    err_UPDATE_TIMEOUT: 'Update check timed out',
    err_UPDATE_TOO_LARGE: 'The release manifest is unexpectedly large',
    err_UPDATE_INVALID: 'The release manifest is invalid',
    err_UPDATE_SIGNATURE: 'The release manifest signature is missing or invalid; the update was refused.',
    err_UPDATE_FAILED: 'Update check failed',
    err_unknown: 'Connection failed for an unknown reason'
  }
};

let settings = {
  language: 'ar',
  disclosureAccepted: false,
  rememberCredentials: false,
  username: '',
  hasPrivateProfile: false,
  privateProfileName: '',
  privateProfileExpiresAt: 0,
  encryptionAvailable: false,
  engine: { found: false, path: '', preferred: '' },
  version: ''
};

let sessionState = {
  status: 'DISCONNECTED',
  server: null,
  isPrivate: false,
  detail: null,
  error: null,
  exitIp: null,
  latencyMs: null,
  measuredMbps: null,
  measuredSource: null,
  exitSource: null,
  downloadBytes: 0,
  uploadBytes: 0,
  startedAt: null,
  protocol: null
};
let selectedId = null;
let pendingConnect = null;
let toastTimer = null;
let guardReport = null;
let intelData = null;
let guardBusy = false;
let intelBusy = false;

function lang() {
  return settings.language === 'en' ? 'en' : 'ar';
}

function t(key, vars) {
  const table = DICT[lang()] || DICT.ar;
  let value = table[key] != null ? table[key] : DICT.ar[key];
  if (value == null) value = key;
  if (vars) {
    for (const [name, replacement] of Object.entries(vars)) {
      value = value.replace(`{${name}}`, String(replacement));
    }
  }
  return value;
}

function errText(code) {
  const key = `err_${code}`;
  const table = DICT[lang()] || DICT.ar;
  return table[key] != null ? table[key] : table.err_unknown;
}

/* ---------- toast ---------- */

function toast(message) {
  const node = $('toast');
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.hidden = true;
  }, 3800);
}

/* ---------- language ---------- */

function applyLanguage(next) {
  settings.language = next === 'en' ? 'en' : 'ar';
  const l = lang();
  document.documentElement.lang = l;
  document.documentElement.dir = l === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
    node.placeholder = t(node.dataset.i18nPlaceholder);
  });
  document.querySelectorAll('[data-lang]').forEach((button) => {
    button.classList.toggle('active', button.dataset.lang === l);
  });
  renderAll();
}

/* ---------- formatting ---------- */

function pad(number) {
  return String(number).padStart(2, '0');
}

function durationText() {
  if (sessionState.status !== 'CONNECTED' || !sessionState.startedAt) return '00:00:00';
  const seconds = Math.max(0, Math.floor((Date.now() - sessionState.startedAt) / 1000));
  return `${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
}

function byteText(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return t('untitled');
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function updatedText() {
  if (!fetchedAt) return lang() === 'ar' ? 'لم تُحدَّث بعد' : 'not updated yet';
  const date = new Date(fetchedAt);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function timeText(ms) {
  if (!ms) return t('untitled');
  const date = new Date(ms);
  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  if (date.toDateString() === new Date().toDateString()) return clock;
  return `${pad(date.getDate())}/${pad(date.getMonth() + 1)} ${clock}`;
}

/* ---------- selection ---------- */

function idExists(id) {
  return id === 'private' && settings.hasPrivateProfile;
}

function ensureSelection() {
  if (idExists(selectedId)) return;
  selectedId = settings.hasPrivateProfile ? 'private' : null;
}

function selectedLabel() {
  if (selectedId === 'private') return settings.privateProfileName || t('privateLabel');
  return selectedId === 'private' ? (settings.privateProfileName || t('privateLabel')) : t('untitled');
}

function selectServer(id) {
  selectedId = id;
  renderSession();
}

/* ---------- rendering ---------- */

function liveTarget() {
  return Boolean(sessionState.server) && sessionState.status !== 'DISCONNECTED';
}

function renderSession() {
  const state = sessionState;
  const orb = $('orb');
  orb.classList.toggle('is-connected', state.status === 'CONNECTED');
  orb.classList.toggle('is-busy', state.status === 'CONNECTING' || state.status === 'DISCONNECTING');
  orb.classList.toggle('is-failed', state.status === 'FAILED');
  orb.setAttribute('aria-label', state.status === 'CONNECTED' ? t('disconnect') : t('connect'));

  const statusNode = $('home-status');
  statusNode.textContent = t(`status_${state.status}`);
  statusNode.classList.toggle('connected', state.status === 'CONNECTED');
  statusNode.classList.toggle('failed', state.status === 'FAILED');

  let substatus = t('subDisconnected');
  if (state.status === 'CONNECTING') {
    substatus = state.detail === 'reconnecting' ? t('subReconnecting') : t('subConnecting');
  } else if (state.status === 'CONNECTED') {
    substatus = t('subConnected');
  } else if (state.status === 'DISCONNECTING') {
    substatus = t('subDisconnecting');
  } else if (state.status === 'FAILED') {
    substatus = errText(state.error || 'unknown');
  }
  $('home-substatus').textContent = substatus;

  const showingLive = liveTarget();
  $('home-selected-name').textContent = showingLive ? t('privateLabel') : selectedLabel();
  $('home-server-name').textContent = showingLive ? t('privateLabel') : selectedLabel();
  $('home-server-meta').textContent = showingLive ? (state.server.host || t('privateMeta')) : t('notConnected');
  $('home-badge').textContent = t('badgePrivate');

  $('home-protocol').textContent = state.protocol || t('untitled');
  $('home-server').textContent = showingLive ? state.server.host || t('untitled') : t('untitled');
  $('home-ip').textContent = state.exitIp || t('untitled');

  const connected = state.status === 'CONNECTED';
  $('home-ping').textContent = connected && state.latencyMs != null ? `${state.latencyMs} ms` : t('untitled');
  $('home-down').textContent = connected ? byteText(state.downloadBytes) : t('untitled');
  $('home-up').textContent = connected ? byteText(state.uploadBytes) : t('untitled');
  $('home-duration').textContent = durationText();

  renderEngineBanner();
}

function renderEngineBanner() {
  const banner = $('engine-banner');
  if (settings.engine && settings.engine.found) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  banner.textContent = t('engineBanner');
}

function renderStats() {
  const state = sessionState;
  $('stats-session').textContent = liveTarget()
    ? state.isPrivate
      ? t('privateLabel')
      : `${state.server.country || ''} ${state.server.host}`.trim()
    : t('noSession');

  $('stats-speed').textContent =
    state.measuredMbps != null ? `${state.measuredMbps.toFixed(1)} Mbps` : t('untitled');
  $('stats-source').textContent = state.measuredSource
    ? t('viaSource', { source: state.measuredSource })
    : t('notMeasured');
  $('stats-ip').textContent = state.exitIp || t('untitled');
  $('stats-probe').textContent = state.detail === 'probe-failed'
    ? t('probeFail')
    : state.exitIp
      ? t('probeOk')
      : t('probeNone');
  $('stats-duration').textContent = durationText();
  $('stats-downloaded').textContent = byteText(state.downloadBytes);
  $('stats-uploaded').textContent = byteText(state.uploadBytes);
}

function renderServers() {
  const meta = $('servers-meta');
  meta.textContent = servers.length
    ? t('serversCount', { n: servers.length, when: updatedText() })
    : t('serversEmpty');

  const list = $('server-list');
  list.textContent = '';

  const needle = query.trim().toLowerCase();
  const visible = servers.filter((server) => {
    if (!needle) return true;
    return (
      (server.country || '').toLowerCase().includes(needle) ||
      (server.host || '').toLowerCase().includes(needle) ||
      (server.countryCode || '').toLowerCase().includes(needle)
    );
  });

  if (!visible.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-note';
    empty.textContent = servers.length ? t('searchEmpty') : t('serversEmpty');
    list.append(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const server of visible) {
    const row = document.createElement('div');
    row.className = 'server-item' + (server.id === selectedId ? ' selected' : '');
    row.tabIndex = 0;
    row.setAttribute('role', 'button');

    const main = document.createElement('div');
    main.className = 's-main';
    const country = document.createElement('span');
    country.className = 's-country';
    country.textContent = server.country || server.host;
    const host = document.createElement('span');
    host.className = 's-host';
    host.textContent = server.host;
    main.append(country, host);

    const side = document.createElement('div');
    side.className = 's-side';
    const ping = document.createElement('span');
    ping.className = 's-ping' + (server.latencyMs == null ? ' hint' : '');
    if (server.latencyMs != null) ping.textContent = `${server.latencyMs} ms`;
    else if (server.pingHintMs != null) ping.textContent = `~${server.pingHintMs} ms`;
    else ping.textContent = t('untitled');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn mini';
    button.textContent = t('connect');
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      selectServer(server.id);
      attempt(server.id);
    });
    side.append(ping, button);

    row.append(main, side);
    row.addEventListener('click', () => selectServer(server.id));
    row.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectServer(server.id);
      }
    });
    fragment.append(row);
  }
  list.append(fragment);
}

function renderPrivateRow() {
  const holder = $('private-row');
  holder.textContent = '';
  if (!settings.hasPrivateProfile) return;

  const row = document.createElement('div');
  row.className = 'server-item private-row' + (selectedId === 'private' ? ' selected' : '');
  row.tabIndex = 0;
  row.setAttribute('role', 'button');

  const main = document.createElement('div');
  main.className = 's-main';
  const title = document.createElement('span');
  title.className = 's-country';
  title.textContent = t('privateLabel');
  const name = document.createElement('span');
  name.className = 's-host';
  name.textContent = settings.privateProfileName || t('privateMeta');
  main.append(title, name);

  const side = document.createElement('div');
  side.className = 's-side';
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'btn mini';
  button.textContent = t('connect');
  button.addEventListener('click', (event) => {
    event.stopPropagation();
    selectServer('private');
    attempt('private');
  });
  side.append(button);

  row.append(main, side);
  row.addEventListener('click', () => selectServer('private'));
  holder.append(row);
}

function renderSettings() {
  $('kill-switch').checked = Boolean(settings.killSwitchEnabled);
  $('kill-switch-strict').checked = settings.killSwitchStrict !== false;
  const locked = Boolean(settings.killSwitchLocked);
  $('kill-lock').hidden = !locked;
  $('restore-network').hidden = !locked;
  $('release-feed').value = settings.releaseFeedUrl || '';
  $('update-status').textContent = settings.releaseFeedUrl ? '' : t('updateNotConfigured');
  if (!settings.hasPrivateProfile) {
    $('profile-status').textContent = t('profileNone');
  } else if (Number(settings.privateProfileExpiresAt) > 0) {
    const date = new Date(Number(settings.privateProfileExpiresAt)).toLocaleDateString(lang() === 'ar' ? 'ar-IQ' : 'en-GB');
    $('profile-status').textContent = `${settings.privateProfileName || t('privateLabel')} — ${t('profileExpires', { date })}`;
  } else {
    $('profile-status').textContent = `${settings.privateProfileName || t('privateLabel')} — ${t('profileExpiryUnknown')}`;
  }
  $('remove-profile').disabled = !settings.hasPrivateProfile;

  const engine = settings.engine || { found: false, path: '' };
  $('engine-status').textContent = engine.found ? engine.path : t('engineNone');
  $('engine-strict').checked = settings.engineStrict !== false;

  $('disclosure-status').textContent = settings.disclosureAccepted ? t('disclosureOn') : t('disclosureOff');
  $('about-text').textContent = t('aboutText', { version: settings.version || '0.1.0' });
}

function renderGuard() {
  const dot = $('guard-dot');
  const level = guardReport && guardReport.level ? guardReport.level : 'idle';
  dot.className = `guard-dot is-${level}`;

  const alertNode = $('guard-alert');
  if (level === 'critical' || level === 'warn') {
    alertNode.hidden = false;
    alertNode.textContent = t(level === 'critical' ? 'guardAlertCritical' : 'guardAlertWarn');
    alertNode.classList.toggle('is-warn', level === 'warn');
  } else {
    alertNode.hidden = true;
  }
  $('guard-when').textContent = guardReport
    ? t('guardAt', { time: timeText(guardReport.at) })
    : t('guardNever');

  const list = $('guard-list');
  list.textContent = '';
  const checks = guardReport && Array.isArray(guardReport.checks) ? guardReport.checks : [];
  if (!checks.length) {
    const note = document.createElement('p');
    note.className = 'muted';
    note.textContent = t('guardIdleHint');
    list.append(note);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const check of checks) {
    const row = document.createElement('div');
    row.className = 'guard-row';

    const label = document.createElement('b');
    label.className = 'guard-label';
    label.textContent = t(`check_${check.id}`);

    const chip = document.createElement('span');
    chip.className = `guard-chip is-${check.level || 'unknown'}`;
    chip.textContent = t(`level_${check.level || 'unknown'}`);

    const evidence = document.createElement('span');
    evidence.className = 'guard-evidence';
    evidence.dir = 'auto';
    evidence.textContent = t(`guard_${check.code || 'idle'}`, check.data || {});

    row.append(label, chip, evidence);
    fragment.append(row);
  }
  list.append(fragment);
}

function intelSeverity(item) {
  const severity = String((item && item.severity) || 'unknown').toUpperCase();
  if (severity === 'KNOWN_EXPLOITED') return { label: t('intelKev'), css: 'KEV' };
  return { label: severity, css: /^[A-Z_]+$/.test(severity) ? severity : 'UNKNOWN' };
}

function renderIntel() {
  const when = $('intel-when');
  const list = $('intel-list');
  list.textContent = '';
  const items = intelData && Array.isArray(intelData.items) ? intelData.items : [];
  if (!items.length) {
    when.textContent = t('intelEmpty');
    return;
  }
  when.textContent = t('intelWhen', { time: timeText(intelData.fetchedAt), n: items.length });

  const visible = items.slice(0, 6);
  const fragment = document.createDocumentFragment();
  for (const item of visible) {
    const row = document.createElement('li');
    row.className = 'intel-item';

    const severity = intelSeverity(item);
    const chip = document.createElement('span');
    chip.className = `intel-sev sev-${severity.css}`;
    chip.textContent = severity.label;

    const body = document.createElement('div');
    body.className = 'intel-body';
    const title = document.createElement('div');
    title.className = 'intel-title';
    title.dir = 'auto';
    title.textContent = item.title || item.id || t('untitled');
    const meta = document.createElement('div');
    meta.className = 'intel-meta';
    meta.dir = 'ltr';
    meta.textContent = [item.id, item.published, item.source].filter(Boolean).join(' · ');
    body.append(title, meta);

    row.append(chip, body);
    if (String(item.url || '').startsWith('https://nvd.nist.gov/')) {
      row.tabIndex = 0;
      row.setAttribute('role', 'link');
      row.title = t('intelTitle');
      const open = () => window.aivpn.openIntel(item.url);
      row.addEventListener('click', open);
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          open();
        }
      });
    }
    fragment.append(row);
  }
  list.append(fragment);

  if (items.length > visible.length) {
    const more = document.createElement('li');
    more.className = 'intel-more';
    more.textContent = t('intelMore', { n: items.length - visible.length });
    list.append(more);
  }
}

function renderAll() {
  renderSession();
  renderStats();
  renderSettings();
  renderGuard();
  renderIntel();
}

/* ---------- tabs ---------- */

function goto(tab) {
  document.querySelectorAll('.tab').forEach((section) => {
    section.hidden = section.dataset.tab !== tab;
  });
  document.querySelectorAll('.tabbar button').forEach((button) => {
    button.classList.toggle('active', button.dataset.goto === tab);
  });
}

/* ---------- data updates ---------- */

function applyState(state) {
  if (!state) return;
  sessionState = state;
  renderSession();
  renderStats();
}

function mergeSettings(next) {
  if (!next) return;
  settings = { ...settings, ...next };
  renderSettings();
  renderEngineBanner();
  renderSession();
}

function setServers(nextServers, nextFetchedAt) {
  if (Array.isArray(nextServers)) servers = nextServers;
  if (typeof nextFetchedAt === 'number') fetchedAt = nextFetchedAt;
  ensureSelection();
  renderServers();
  renderPrivateRow();
  renderSession();
}

async function doRefresh(silent) {
  const button = $('refresh-btn');
  refreshBusy = true;
  button.disabled = true;
  button.textContent = t('refreshing');
  try {
    const result = await window.aivpn.refresh();
    if (result && result.ok) {
      setServers(result.servers, result.fetchedAt);
      if (!silent) toast(t('refreshed'));
      return true;
    }
    toast(t('refreshFailed'));
    return false;
  } catch {
    toast(t('refreshFailed'));
    return false;
  } finally {
    refreshBusy = false;
    button.disabled = false;
    button.textContent = t('refresh');
  }
}

/* ---------- disclosure ---------- */

function showDisclosure() {
  const modal = $('disclosure-modal');
  modal.hidden = false;
  $('disclosure-accept').focus();
}

function hideDisclosure() {
  $('disclosure-modal').hidden = true;
}

/* ---------- connect ---------- */

async function attempt(id, retried) {
  if (!id) {
    toast(t('privateMissing'));
    goto('settings');
    return;
  }
  if (id === 'private' && !settings.hasPrivateProfile) {
    toast(t('privateMissing'));
    goto('settings');
    return;
  }
  if (!settings.disclosureAccepted) {
    pendingConnect = id;
    showDisclosure();
    return;
  }
  if (!settings.engine || !settings.engine.found) {
    toast(t('engineMissingShort'));
    goto('settings');
    return;
  }
  if (['CONNECTING', 'CONNECTED', 'DISCONNECTING'].includes(sessionState.status)) return;

  const result = await window.aivpn.connect(id);
  if (result && result.needDisclosure) {
    pendingConnect = id;
    showDisclosure();
    return;
  }
  if (result && result.state) applyState(result.state);
  if (result && result.error) toast(errText(result.error));
}

async function onOrb() {
  const status = sessionState.status;
  if (status === 'CONNECTED') {
    const state = await window.aivpn.disconnect();
    applyState(state);
    return;
  }
  if (status === 'CONNECTING' || status === 'DISCONNECTING') return;
  ensureSelection();
  await attempt(selectedId);
}

/* ---------- wiring ---------- */

function wire() {
  document.querySelectorAll('[data-lang]').forEach((button) => {
    button.addEventListener('click', async () => {
      const next = button.dataset.lang;
      if (next === lang()) return;
      applyLanguage(next);
      try {
        const result = await window.aivpn.updateSettings({ language: lang() });
        mergeSettings(result && result.settings);
      } catch {
        // language is a local preference; keep the UI responsive
      }
    });
  });

  document.querySelectorAll('.tabbar button').forEach((button) => {
    button.addEventListener('click', () => goto(button.dataset.goto));
  });

  $('home-select').addEventListener('click', () => goto('settings'));
  $('orb').addEventListener('click', onOrb);
  $('engine-banner').addEventListener('click', () => goto('settings'));
  $('guard-alert').addEventListener('click', () => goto('stats'));

  $('import-profile').addEventListener('click', async () => {
    const result = await window.aivpn.importProfile();
    if (!result || result.canceled) return;
    if (result.error) {
      toast(result.error === 'PROFILE_TOO_LARGE' ? errText('PROFILE_TOO_LARGE') : errText('PROFILE_INVALID'));
      return;
    }
    mergeSettings(result.settings);
    ensureSelection();
    renderAll();
    toast(t('profileImported'));
  });

  $('remove-profile').addEventListener('click', async () => {
    const result = await window.aivpn.removeProfile();
    mergeSettings(result && result.settings);
    if (selectedId === 'private') selectedId = null;
    ensureSelection();
    renderAll();
    toast(t('profileRemoved'));
  });

  $('pick-engine').addEventListener('click', async () => {
    const result = await window.aivpn.pickEngine();
    if (!result || result.canceled) return;
    mergeSettings(result.settings);
    renderAll();
  });

  $('kill-switch').addEventListener('change', async (event) => {
    const result = await window.aivpn.updateSettings({ killSwitchEnabled: event.target.checked });
    mergeSettings(result && result.settings);
  });

  $('kill-switch-strict').addEventListener('change', async (event) => {
    const result = await window.aivpn.updateSettings({ killSwitchStrict: event.target.checked });
    mergeSettings(result && result.settings);
  });

  $('restore-network').addEventListener('click', async () => {
    const result = await window.aivpn.restoreNetwork();
    mergeSettings(result && result.settings);
    if (result && result.error === 'KILLSWITCH_ELEVATION_CANCELLED') {
      toast(t('restoreCancelled'));
    } else if (result && result.error) {
      toast(errText(result.error));
    } else if (result && result.ok) {
      toast(t('restoreDone'));
    }
  });


  $('engine-strict').addEventListener('change', async (event) => {
    const result = await window.aivpn.updateSettings({ engineStrict: event.target.checked });
    mergeSettings(result && result.settings);
  });

  $('repin-cert').addEventListener('click', async () => {
    const result = await window.aivpn.repinServer();
    if (result && result.report) {
      guardReport = result.report;
      renderGuard();
    }
    toast(t(result && result.cleared ? 'repinDone' : 'repinNone'));
  });

  $('release-feed').addEventListener('change', async (event) => {
    const result = await window.aivpn.updateSettings({ releaseFeedUrl: event.target.value.trim() });
    if (result && result.error) { toast(errText(result.error)); renderSettings(); return; }
    mergeSettings(result && result.settings);
  });

  $('check-update').addEventListener('click', async () => {
    const button = $('check-update');
    button.disabled = true;
    $('update-status').textContent = t('updateChecking');
    try {
      const result = await window.aivpn.checkForUpdate();
      if (!result || result.error) { $('update-status').textContent = errText((result && result.error) || 'UPDATE_FAILED'); return; }
      $('update-status').textContent = result.available ? t('updateAvailable', { version: result.latest }) : t('updateCurrent', { version: result.current });
    } catch { $('update-status').textContent = errText('UPDATE_FAILED'); }
    finally { button.disabled = false; }
  });

  $('guard-check').addEventListener('click', async () => {
    if (guardBusy) return;
    guardBusy = true;
    const button = $('guard-check');
    button.disabled = true;
    button.textContent = t('guardChecking');
    try {
      const result = await window.aivpn.guardCheck();
      if (result && result.report) guardReport = result.report;
      if (result && result.intel) intelData = result.intel;
      renderGuard();
      renderIntel();
    } catch {
      toast(t('err_unknown'));
    } finally {
      guardBusy = false;
      button.disabled = false;
      button.textContent = t('guardCheck');
    }
  });

  $('intel-refresh').addEventListener('click', async () => {
    if (intelBusy) return;
    intelBusy = true;
    const button = $('intel-refresh');
    button.disabled = true;
    button.textContent = t('refreshing');
    try {
      const result = await window.aivpn.refreshIntel();
      if (result && result.intel) intelData = result.intel;
      renderIntel();
      toast(t('refreshed'));
    } catch {
      toast(t('intelFailed'));
    } finally {
      intelBusy = false;
      button.disabled = false;
      button.textContent = t('refreshIntel');
    }
  });

  $('reset-disclosure').addEventListener('click', async () => {
    const result = await window.aivpn.updateSettings({ disclosureAccepted: false });
    mergeSettings(result && result.settings);
    toast(t('disclosureOff'));
  });

  $('disclosure-cancel').addEventListener('click', () => {
    pendingConnect = null;
    hideDisclosure();
  });

  $('disclosure-accept').addEventListener('click', async () => {
    const target = pendingConnect;
    pendingConnect = null;
    hideDisclosure();
    try {
      const result = await window.aivpn.updateSettings({ disclosureAccepted: true });
      mergeSettings(result && result.settings);
    } catch {
      settings.disclosureAccepted = true;
    }
    if (target) attempt(target);
  });

  $('disclosure-modal').addEventListener('click', (event) => {
    if (event.target === $('disclosure-modal')) {
      pendingConnect = null;
      hideDisclosure();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !$('disclosure-modal').hidden) {
      pendingConnect = null;
      hideDisclosure();
    }
  });
}

/* ---------- boot ---------- */

async function boot() {
  wire();
  setInterval(() => {
    const text = durationText();
    $('home-duration').textContent = text;
    $('stats-duration').textContent = text;
  }, 1000);

  try {
    const data = await window.aivpn.init();
    if (data && data.settings) settings = { ...settings, ...data.settings };
    if (data && data.state) sessionState = data.state;
    if (data && data.guard) guardReport = data.guard;
    if (data && data.intel) intelData = data.intel;
  } catch {
    toast(t('err_unknown'));
  }

  applyLanguage(settings.language);
  ensureSelection();
  renderAll();

  window.aivpn.onState((state) => applyState(state));
  window.aivpn.onGuard((payload) => {
    if (payload && payload.report) guardReport = payload.report;
    if (payload && payload.intel) intelData = payload.intel;
    renderGuard();
    renderIntel();
  });
  window.aivpn.onGuardFocus(() => {
    goto('stats');
    renderGuard();
    $('guard-card')?.scrollIntoView({ block: 'center' });
  });
}

boot();
