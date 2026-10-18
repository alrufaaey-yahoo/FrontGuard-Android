# Google Apps Script Relay في FrontGuard

ميزة **Google Apps Script Relay** مسار مستقل تمامًا عن Front/SNI: يتصل التطبيق بـ`script.google.com` عبر HTTPS عادي ويتابع redirect إلى `googleusercontent.com`. لا يستخدم Relay قائمة `Fronts` ولا شهادة MITM للوصول إلى Google. أما `Fronts` و`SNI mode` وشهادة MITM فتُستخدم فقط عندما يعمل مسار Front التقليدي.

## النشر

1. افتح Google Apps Script وأنشئ مشروعًا جديدًا.
2. انسخ محتوى [`assets/apps_script/Code.gs`](../assets/apps_script/Code.gs) كاملًا.
3. غيّر `AUTH_KEY` إلى سر قوي، ثم أنشئ Deployment من نوع Web app مع `Execute as: Me` و`Who has access: Anyone`.
4. ضع رابط `/exec` و`AUTH_KEY` نفسيهما داخل بطاقة Relay في التطبيق.
5. فعّل MITM وثبّت شهادة CA المصدّرة من التطبيق على الجهاز قبل اختبار HTTPS. في وضع Relay المستقل لا يتم استخدام Front أو SNI للوصول إلى Apps Script.

## ملاحظات التشغيل

- HTTP يعمل مباشرة عبر Relay.
- HTTPS يحتاج MITM وشهادة CA محلية يثبتها المستخدم؛ هذه الشهادة لا تُدمج مع شهادة Google ولا تُرسل إلى Apps Script. التطبيقات التي تستخدم Certificate Pinning وWebSocket ليست مدعومة عبر Apps Script.
- ظهور `SSLV3_ALERT_CERTIFICATE_UNKNOWN` في `mitm handshake` يعني أن المتصفح لم يثق بشهادة CA المحلية؛ أعد تصدير شهادة FrontGuard وثبّتها من إعدادات Android، ثم أعد تشغيل المتصفح.
- ظهور `Trust anchor for certification path not found` في اتصال Relay يعني أن تحقق Android من شهادة Google فشل. اترك `Verify upstream TLS` مفعّلًا في الوضع الطبيعي، وأوقفه مؤقتًا للتشخيص فقط إذا كانت الشبكة تستبدل شهادات Google أو كان الجهاز يفتقد مخزن الشهادات الصحيح.
- ردود Apps Script قد تمر بإعادة توجيه إلى `googleusercontent.com`؛ التطبيق يتبعها بالطريقة المتوافقة مع البروتوكول: POST أولي ثم GET للرابط النهائي.
- حدود الحجم والحصص والمهلة تفرضها Google Apps Script، لذلك تظهر الأخطاء التفصيلية في نافذة السجل.
- لا تضع `AUTH_KEY` في المستودع العام أو داخل هذا الملف؛ عدّل القيمة داخل مشروع Apps Script فقط.
