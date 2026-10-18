# Google Apps Script Relay في FrontGuard

ميزة **Google Apps Script Relay** مسار مستقل عن Front/SNI. يرسل التطبيق طلب HTTP/HTTPS إلى رابط Apps Script، ويأخذ `Host` الهدف من طلب المستخدم، بينما إعداد `SNI mode` وقائمة `Fronts` تخص مسار Front فقط.

## النشر

1. افتح Google Apps Script وأنشئ مشروعًا جديدًا.
2. انسخ محتوى [`assets/apps_script/Code.gs`](../assets/apps_script/Code.gs) كاملًا.
3. غيّر `AUTH_KEY` إلى سر قوي، ثم أنشئ Deployment من نوع Web app مع `Execute as: Me` و`Who has access: Anyone`.
4. ضع رابط `/exec` و`AUTH_KEY` نفسيهما داخل بطاقة Relay في التطبيق.
5. فعّل MITM وثبّت شهادة CA المصدّرة من التطبيق على الجهاز قبل اختبار HTTPS.

## ملاحظات التشغيل

- HTTP يعمل مباشرة عبر Relay.
- HTTPS يحتاج MITM وشهادة CA؛ التطبيقات التي تستخدم Certificate Pinning وWebSocket ليست مدعومة عبر Apps Script.
- ردود Apps Script قد تمر بإعادة توجيه إلى `googleusercontent.com`؛ التطبيق يتبعها بالطريقة المتوافقة مع بروتوكول المرجع: POST أولي ثم GET للرابط النهائي.
- حدود الحجم والحصص والمهلة تفرضها Google Apps Script، لذلك تظهر الأخطاء التفصيلية في نافذة السجل.
- لا تضع `AUTH_KEY` في المستودع العام أو داخل هذا الملف؛ عدّل القيمة داخل مشروع Apps Script فقط.
