# DEPI — شرح الأسبوع الأول بالتفصيل

**Phishing & Initial Access Analysis | تحليل رسالة التصيّد وجمع الأدلة الأولية**

في الأسبوع الأول بنبدأ بملف إيميل محلي، ونحلّل محتواه من غير تشغيل المرفقات أو زيارة الروابط. الناتج الأساسي تقرير JSON لكل رسالة. منه بنقرأ مصدر الرسالة المعلن، نتائج التوثيق المسجّلة، الروابط والمرفقات، أسباب درجة الخطورة، وتقنيات MITRE ATT&CK اللي الأدلة بتدعمها. بعد كده بنستخدم النتائج دي كمدخلات للـ Detection والـ Triage في الأسبوع الثاني.

## 1. اعرف دور كل ملف

| الملف داخل المشروع | دوره |
| --- | --- |
| `main.py` | نقطة تشغيل الأداة. بتاخد ملف أو أكتر وتطبع التقارير أو تحفظها JSON. |
| `email_analyzer/email_parser.py` | بيفك بنية رسالة EML، يقرا الـ headers والـ MIME parts، ويسجّل بيانات المرفقات والـ SHA-256. |
| `email_analyzer/header_analyzer.py` | بيقارن دومينات المرسل والرد والارتداد، ويرتب الـ Received hops، ويقرأ نتائج SPF وDKIM وDMARC المسجّلة. |
| `email_analyzer/pipeline.py` | بيجمع نتائج التحليل، يفحص الروابط، ويربط المراحل ببعض عشان ينتج التقرير. |
| `email_analyzer/analysis_modules.py` | بيستخرج الـ IOCs ويحسب درجة الخطورة ويفحص ملف VBA لو اتمرّر له صراحةً. |
| `email_analyzer/mitre_mapper.py` | بيربط الأدلة بتقنيات ATT&CK ويذكر سبب كل ربط أو استبعاد. |
| `email_analyzer/samples/` | العينات التدريبية الأربع، ملف VBA تجريبي، وملف `sample_inventory.csv` لتوثيق مصدر العينات. |
| `reports/week_1/` | التقرير الأصلي والأدلة المحفوظة في المشروع. |

## 2. جهّز البيئة وشغّل العينات

افتح PowerShell من جذر المشروع. لو عندك بالفعل `venv` وفيها الاعتماديات، ابدأ من خطوة التشغيل تحت.

```powershell
Set-Location 'D:\repos\DEPI_GP'
python -m venv venv
& .\venv\Scripts\python.exe -m pip install -r requirements.txt
```

الأوامر هنا بتستخدم Python من داخل البيئة الافتراضية مباشرةً. شغّل العينات الأربع واحفظ تقرير كل رسالة في مجلد تشغيل جديد.

```powershell
$run = 'reports/generated/week1-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
& .\venv\Scripts\python.exe main.py --output-dir $run
Get-ChildItem -LiteralPath $run
```

من غير تحديد أي مدخلات، الأداة بتشغّل ملفات EML التدريبية الموجودة في `email_analyzer/samples/`. كل اسم خرج بالشكل `اسم-الرسالة.eml.json`، والعينات المدمجة بتاخد `mitre.provenance = simulated`. لو شغّلت `main.py` من غير `--output-dir`، هتلاقي النتائج مطبوعة في التيرمنال. مجلد خرج جديد في كل مرة بيفصل التشغيلات ويمنع خطأ تعارض أسماء التقارير.

| العينة | النتيجة المتوقعة | هتراجع إيه؟ |
| --- | --- | --- |
| `phish_001.eml` | `70 / high / suspicious` | الرسالة فيها دلائل متجمعة من التوثيق واللينك والمرفق ولغة الاستعجال. |
| `benign_001.eml` | `0 / low / inconclusive` | التوثيق المسجّل كله `pass` والعينة بتستخدم للمقارنة. اسمها التدريبي benign، وحقل verdict في الكود بيبقى `inconclusive` لأي نتيجة منخفضة. |
| `incomplete_001.eml` | `0 / low / inconclusive` | نتائج التوثيق `unknown`. افحص الحقول الناقصة قبل ما تفسّر الدرجة. |
| `malformed_001.eml` | `0 / low / inconclusive` | `parsed.defects` فيه `MissingHeaderBodySeparatorDefect`. افتح التقرير وشوف مستوى اكتمال التحليل قبل الاعتماد على النتيجة. |

## 3. اقرأ التقرير بنفسك خطوة بخطوة

```powershell
$r = Get-Content -LiteralPath (Join-Path $run 'phish_001.eml.json') -Raw | ConvertFrom-Json
$r.parsed.headers
$r.parsed.defects
$r.parsed.parse_errors
$r.headers.authentication
$r.headers.hops | Format-Table timestamp_raw,from_host,by_host,ips
$r.headers.findings | Format-List id,kind,severity,detail,evidence
$r.urls | Format-List url,suspicious,reasons
$r.parsed.attachments | Format-List filename,extension,content_type,size,sha256,detected_type
$r.iocs | ConvertTo-Json -Depth 6
$r.risk | ConvertTo-Json -Depth 5
$r.mitre.mapped | Format-Table technique_id,status,confidence
$r.mitre.not_mapped | Format-Table technique_id,area,reason -Wrap
```

### أ. اتأكد من بنية الرسالة والأدلة الأصلية

ملف EML بيضم معلومات الرسالة الأصلية في الـ headers، ومعاها الـ body وأجزاء MIME. الـ MIME هو اللي بيسمح بتجميع نسخة نصية ونسخة HTML ومرفقات في رسالة واحدة. الأداة بتقرأ البايتات، تحسب بصمة الرسالة كلها في `parsed.message_sha256`، وتفصل المرفقات عن نص الرسالة أثناء التحليل من غير ما تنفّذها أو تحفظها كملفات مستقلة. لو ظهر `defect`، راجع الجزء المتأثر. لو ظهر `parse_errors`، الأداة ممكن تكتب التقرير المتاح وترجع كود خروج `1`. اقرأ الاتنين قبل تفسير الدرجة.

### ب. حلّل الـ Headers والتوثيق

| الحقل | تقراه إزاي في العينة؟ |
| --- | --- |
| `From` | الاسم الظاهر `Microsoft Support`، وعنوان المرسل المعلن في دومين `micros0ft-security.invalid` فيه صفر مكان حرف o. |
| `Reply-To` | الرد يتوجّه لدومين `evil-reply.invalid`، وده بيفسّر finding اسمه `reply_to_mismatch`. |
| `Return-Path` | عنوان رجوع رسائل الارتداد في دومين `random-host.invalid`. الاختلاف ممكن يظهر كمان مع خدمات إرسال وقوائم بريد، فاقراه مع باقي الأدلة. |
| `Message-ID` | معرّف الرسالة، ودومينه في العينة كمان `random-host.invalid`. احتفظ بالمعرّف للمطابقة بين السجلات. |
| `Received` | كل سطر بيسجّل مرور الرسالة بخادم بريد. ترتيب الحقول الأصلية من الأحدث للأقدم. `headers.hops` بيعرضها من الأقدم للأحدث. المثال فيه نقلتين، والـ IPs المسجّلة `203.0.113.45` و`198.51.100.23`. |

| طريقة التوثيق | بتفحص إيه في نظام البريد؟ | المسجّل في عينة التصيّد |
| --- | --- | --- |
| SPF | هل خادم الإرسال مسموح له بالإرسال باسم دومين عنوان الـ envelope sender؟ | `fail` |
| DKIM | هل التوقيع الرقمي المضاف للرسالة صالح وفق المفتاح العام لدومين التوقيع؟ | `none` |
| DMARC | هل فيه SPF أو DKIM ناجح والدومين بتاعه متوافق مع الدومين الظاهر في `From`؟ | `fail` |

الكود بيقرأ القيم المسجّلة في `Authentication-Results`، وبيحط `unknown` لو القيمة غايبة. بيسجّل كمان حقول زي `DKIM-Signature` و`Received-SPF` ضمن بيانات الرسالة. ما بيعملش DNS lookup أو تحقق مستقل من التوقيع. في الإيميل الحقيقي قيّم التوثيق المسجّل حسب مصدر الرسالة والـ mail gateway اللي سجّل النتيجة. [RFC 8601](https://www.rfc-editor.org/info/rfc8601/)

### ج. راجع الروابط والمرفقات والـ IOCs

- **الروابط.** الأداة بتجمع روابط HTTP/HTTPS من النص العادي ومن `href` في روابط HTML. بتسجّل علامات زي عنوان IP كوجهة، دومين فيه Punycode، أو اختلاف دومين الرابط المكتوب في نص الـ HTML عن دومين عنوان `href`. في العينة، الوجهة الفعلية كانت `hxxp://login[.]micros0ft-security[.]invalid/verify?id=123` واتسجّل السبب `visible_destination_mismatch`. فحص الاختلاف ده بيشتغل لما النص الظاهر نفسه عنوان HTTP/HTTPS. زر مكتوب عليه «Log in» ممكن يحتاج مراجعة يدوية لوجهته.
- **المرفقات.** `Invoice_2026.pdf.exe` اسمه فيه امتدادين، والامتداد الأخير اللي الكود استخدمه هو `.exe` وده لوحده ضمن امتدادات المراجعة. حجم المرفق 33 بايت ونوعه المعلن `application/octet-stream`. أول بايتاته ما طابقتش توقيع معروف في الكود، فعشان كده `detected_type = unknown`. سجّل اسم المرفق وبصمته والسبب اللي خلّاه راية اشتباه. بصمة المرفق تخص البايتات بعد فك ترميز MIME. بصمة الرسالة تخص ملف الـ EML كله.
- **الـ IOCs.** هي قيم مرصودة تقدر تبحث عنها في مصادر تانية، زي URL أو دومين أو IP أو عنوان بريد أو SHA-256. `iocs` في JSON بيتكوّن أساسًا من النص العادي وروابط HTML المستخرجة، وفيه كمان بصمات المرفقات تحت `sha256_embedded_attachments`. هات دومينات الـ headers والـ IPs بتاعة الـ Received hops من أقسامها. ملف `reports/week_1/evidence/iocs.csv` مثال جاهز إزاي تجمع المؤشر مع مصدره وسبب أهميته وحالته التدريبية.

### د. افهم درجة الخطورة

اقرأ `risk.reasons` عشان تعرف الدرجة اتجمعت من إيه.

| الإشارة في الكود | وزنها | احتُسبت في العينة الأساسية؟ |
| --- | ---: | --- |
| SPF = `fail` | 10 | أيوه |
| DKIM = `fail` | 10 | لأ، القيمة `none` |
| DMARC = `fail` | 15 | أيوه |
| فيه رابط اتعلّم عليه كمشبوه | 20 | أيوه |
| فيه مرفق اتعلّم عليه للمراجعة | 20 | أيوه |
| ملف الماكرو الممرَّر اتحلل وطلع `high` | 20 | لأ، التشغيل ده للرسالة وحدها |
| ألفاظ استعجال في النص مثل `urgent` أو `immediately` أو `verify now` | 5 | أيوه |

الحساب في العينة هو **10 + 15 + 20 + 20 + 5 = 70**. الحد الأقصى 100. `low` أقل من 30، و`medium` من 30 إلى 69، و`high` من 70 إلى 100. الوزن بيتحسب مرة لكل نوع إشارة، حتى لو فيه أكتر من لينك مشبوه. الـ findings بتاعة اختلاف الدومينات مفيدة للتحقيق، والكود الحالي بيعرضها من غير إضافة نقاط لها مباشرةً. الدرجة لترتيب أولويات المراجعة. راجع الأدلة الناقصة حتى لو الدرجة صفر.

## 4. جرّب تحليل الـ VBA بشكل منفصل

```powershell
$macroRun = Join-Path $run 'macro'
& .\venv\Scripts\python.exe main.py email_analyzer/samples/phish_001.eml --macro-file email_analyzer/samples/demo_macro.bas --output-dir $macroRun
$m = Get-Content -LiteralPath (Join-Path $macroRun 'phish_001.eml.json') -Raw | ConvertFrom-Json
$m.macros | ConvertTo-Json -Depth 6
$m.risk | ConvertTo-Json -Depth 5
```

`--macro-file` بيقبل ملف محلي بتحدده صراحةً مع مدخل رسالة واحد. التحليل ثابت باستخدام `oletools`. في العينة التدريبية ظهر `has_macros = true` و`status = ok` و`risk = high`، ودرجة التشغيل ده بقت **90** لأن الفحص أضاف 20 نقطة. الأداة لقت `AutoOpen` في الكود ولقت كلمات زي `WScript.Shell` و`PowerShell` و`URLDownloadToFile` في تعليق. تسجيل كلمة في تعليق بيوضح حدود الفحص بالكلمات المفتاحية. ملف VBA هنا مستقل عن مرفق الرسالة، فعند توثيق العينة اكتب 70 لتحليل الرسالة، وسجّل نتيجة فحص الماكرو في بند منفصل. لو لقيت `status = error`، راجع حقل `error` وتثبيت الاعتماديات ومسار الملف.

## 5. اربط اللي شفته بـ MITRE ATT&CK

افتح `mitre.mapped` وشوف رقم التقنية والتصنيف ومستوى الثقة والدليل ومصدره. افتح `mitre.not_mapped` عشان تعرف إيه اللي اتراجع وإيه الدليل اللي كان ناقص.

| التقنية | نتيجة عينة التصيّد الأساسية | السبب |
| --- | --- | --- |
| `T1566.001` Spearphishing Attachment | `simulated / medium` | رسالة مشبوهة فيها مرفق موثّق باسمه وبصمته. |
| `T1566.002` Spearphishing Link | `simulated / medium` | اختلاف الدومين الظاهر في اللينك عن الوجهة الفعلية. |
| `T1566` Phishing | الكود اكتفى بالتقنيتين الفرعيتين | لو الرسالة مشبوهة والتقنيات الفرعية ما انطبقتش، الكود ممكن يربط التقنية العامة لو عنده مؤشرات مناسبة في الـ headers. |
| `T1204.002` User Execution: Malicious File | مفيش ربط في تحليل الأسبوع الأول | إثبات التنفيذ يحتاج دليل من الجهاز زي حدث تشغيل عملية مرتبط بالمرفق. |
| Defense Evasion | مفيش تقنية مربوطة | العينة ما فيهاش دليل على حدوث سلوك مراوغة محدد. |

`simulated` يوضح مصدر الدليل التدريبي. في تشغيل ملف حقيقي من خارج مجلد العينات، الأداة بتستخدم `observed` للدلالة على مصدر التحليل. درجة الثقة بتوصف تقييم الكود للربط. الاستلام أو وصول الرسالة للمستخدم دليل على التسليم. علشان توثّق الضغط على اللينك أو فتح الملف أو تنفيذ عملية، هتحتاج أدلة إضافية مرتبطة بالواقعة. [MITRE ATT&CK — Phishing](https://attack.mitre.org/techniques/T1566/) · [MITRE ATT&CK — Malicious File](https://attack.mitre.org/techniques/T1204/002/)

## 6. طبّق نفس الخطوات على إيميل جديد

1. صدّر أصل الرسالة كملف EML من مصدر الرسالة. احتفظ بالأصل عشان يفضل الـ hash والـ headers متاحين للمراجعة.
2. حط الملف الخاص داخل `samples/` في جذر المشروع، واستخدم مساره الفعلي في الأمر. المثال بيفترض اسم `new_email.eml`.
3. شغّل التحليل وراجع التحذيرات وأسباب الدرجة والـ mapping بنفس أوامر القراءة اللي فوق مع تعديل اسم الـ JSON.
4. سجّل في ملاحظاتك رقم الحالة، وقت التحليل، اسم الملف والـ SHA-256، أهم المؤشرات ومصدر كل واحد منها، واللي محتاج تحقق في الأسبوع الثاني. قبل مشاركة التقرير راجع العناوين والمعرّفات والروابط الحساسة واحجبها في نسخة المشاركة.

```powershell
$newRun = 'reports/generated/week1-new-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
& .\venv\Scripts\python.exe main.py .\samples\new_email.eml --output-dir $newRun
Get-ChildItem -LiteralPath $newRun
```

الأداة بتقبل TXT لو المتاح نص منسوخ. في الوضع ده هتطلع IOCs من النص ودرجة حسب الإشارات اللي يقدر يكتشفها، وحقل `headers` هيبقى `null`. استخدم EML لما تحليل التوثيق أو مسار الرسالة أو المرفقات مطلوب. لو عملت عينة تدريبية خاصة بيك، استخدم `--simulated` لتعليم الناتج.

## 7. اختبر التنفيذ وجهّز تسليم الأسبوع الأول

```powershell
& .\venv\Scripts\python.exe -m pytest -q
```

الاختبارات بتغطي قراءة الرسائل والمرفقات، استخراج المؤشرات، الـ headers، الـ risk والـ MITRE mapping. عند التحقق من المشروع، كانت النتيجة **34 passed, 19 warnings** باستخدام البيئة الافتراضية ومجلد مؤقت قابل للكتابة. لو الاختبارات وقفت على خطأ صلاحيات في مجلد Temp، استخدم مجلد جديد قابل للكتابة كما في المثال ده. أوامر `TEMP` و`TMP` هنا بتأثر على جلسة PowerShell الحالية.

```powershell
$testTemp = Join-Path (Resolve-Path $run).Path 'test-temp'
New-Item -ItemType Directory -Path $testTemp | Out-Null
$env:TEMP = $testTemp
$env:TMP = $testTemp
& .\venv\Scripts\python.exe -m pytest -q --basetemp (Join-Path $testTemp 'pytest')
```

| بند التسليم | مكانه في المشروع |
| --- | --- |
| تقرير تحليل الأسبوع الأول | `reports/week_1/Week_1_Phishing_Analysis_Report.md` |
| تقرير لكل عينة | `reports/week_1/evidence/email/` |
| قائمة المؤشرات ومصدر كل مؤشر | `reports/week_1/evidence/iocs.csv` |
| نتيجة تجربة الماكرو المستقلة | `reports/week_1/evidence/macro_analysis.json` |
| إثبات الاختبارات | `reports/week_1/pytest-results.txt` |

بعد ما تكمّل التحليل، خُد للأسبوع الثاني JSON الرسالة المشبوهة والمقارنة السليمة، واحتفظ بـ Message-ID والـ hashes واللينك المشبوه وأسباب الدرجة. الأسبوع الثاني بيستخدم خرج الأداة في اختبار الـ detection على Wazuh والـ triage وربط الرسالة بسجلات تانية. نتيجة الأسبوع الأول بتقول إيه اللي وصل في الإيميل وإيه اللي يستحق مراجعة على الأجهزة وسجلات البريد.

