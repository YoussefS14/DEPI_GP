# DEPI — Phishing Analysis & Incident Response

المشروع بيتتبّع رسالة تصيّد من التحليل الأولي لحد توثيق الاستجابة. أداة Python بتفحص ملف الإيميل محليًا وتطلع تقرير JSON. في الأسبوع الثاني بنحوّل التقرير لحدث يوصّل لـ Wazuh. في الأسبوع الثالث بنجرّب الاحتواء والتنظيف والاسترجاع على صندوق بريد تجريبي محلي. في الأسبوع الرابع بنراجع الأدلة ونكتب التقرير النهائي وإجراءات الاستجابة.

| الأسبوع | المدخل | المخرج | ابدأ من |
| --- | --- | --- | --- |
| 1 — تحليل الإيميل | ملف EML أو TXT | نتائج التحليل بصيغة JSON ومؤشرات الاشتباه (IOCs) | [تقرير الأسبوع الأول](reports/week_1/Week_1_Phishing_Analysis_Report.md) |
| 2 — الكشف والفرز | تقارير JSON من الأسبوع الأول | أحداث JSONL وتنبيهات Wazuh وتحديد مبدئي لنطاق الحالة | [تقرير الأسبوع الثاني](reports/week_2/Week_2_Detection_Triage_and_Scope.md) |
| 3 — الاستجابة | نتائج التحليل والتنبيه وحدود الحالة | خطة الاستجابة ونتائج تمرين الاحتواء والتنظيف والاسترجاع | [خطة الأسبوع الثالث](reports/week_3/Week_3_Incident_Response_Plan.md) |
| 4 — إغلاق الحالة | نتائج التحقيق والاستجابة والأدلة المحفوظة | التقرير النهائي وسجل حيازة الأدلة وخطة الاستجابة المحدّثة | [التقرير النهائي](reports/week_4/Final_IR_Case_Report.md) |

## التشغيل السريع من PowerShell

نفّذ الأوامر من جذر المشروع. لو البيئة الافتراضية `venv` جاهزة، ابدأ من خطوة إنشاء مجلد الخرج.

~~~powershell
python -m venv venv
& .\venv\Scripts\python.exe -m pip install -r requirements.txt
$run = 'reports/generated/week1-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
& .\venv\Scripts\python.exe main.py --output-dir $run
& .\venv\Scripts\python.exe -m pytest -q
~~~

من غير تحديد ملف إدخال، `main.py` بيحلّل عينات EML الأربع المدمجة. من غير `--output-dir`، بيطبع التقارير في التيرمنال. لتحليل إيميل جديد، حط مساره بعد `main.py` وحدد مجلد خرج جديد لكل تشغيل باسم مختلف. `--macro-file` بيحلّل ملف VBA محلي بتحدده مع رسالة واحدة. `--simulated` بيميّز المدخل التدريبي.

التحليل بيقرأ نتائج SPF وDKIM وDMARC اللي اتسجّلت في الرسالة. درجة الخطورة وترشيحات MITRE ATT&CK بتساعد في الفرز. لو محتاج تتأكد من تنفيذ مرفق أو تأثير على جهاز، اربط التقرير بأدلة مستقلة من سجلات الجهاز. استخدم [إعدادات Wazuh](wazuh/README.md) لو هتكمّل للأسبوع الثاني.

## ملفات الجذر

| الملف | بيعمل إيه؟ |
| --- | --- |
| `Readme.md` | دليل تشغيل المشروع وفهرس الملفات اللي بتقرأه دلوقتي. |
| [main.py](main.py) | نقطة تشغيل المحلّل. بتقبل EML أو TXT وتصدر تقرير JSON مستقل لكل مدخل. |
| [requirements.txt](requirements.txt) | إصدارات مكتبات Python المطلوبة، ومنها pytest للاختبارات وoletools لفحص VBA. |
| [pytest.ini](pytest.ini) | بيحدد مجلد الاختبارات وبيضيف جذر المشروع لمسار الاستيراد. |
| [.gitignore](.gitignore) | بيستبعد البيئة الافتراضية والـ cache والعينات الخاصة وملفات الخرج من Git، مع استثناء ملفات EML التدريبية الأربعة. |
| [.gitattributes](.gitattributes) | بيمنع تحويل نهايات السطور في ملفات EML التدريبية عشان بصمات SHA-256 تفضل قابلة للمقارنة. |
| `Tested emails.txt` | ملاحظة محلية مختصرة عن العينات اللي اتجرّبت. |
| [Week_1_Phishing_Analysis_Guide.md](Week_1_Phishing_Analysis_Guide.md) | شرح عملي بالعربي لتشغيل محلّل الإيميل، وقراءة التقارير وتفسير التوثيق والـ IOCs والدرجة. |
| [Week_2_Detection_Triage_Guide.md](Week_2_Detection_Triage_Guide.md) | شرح عملي بالعربي لتجهيز الـ Agent والـ Manager وعمل Replay ومراجعة التنبيه وكتابة الـ Triage. |
| [DEPI_Week_3_Chat.md](DEPI_Week_3_Chat.md) | شرح عملي بالعربي لخطة الأسبوع الثالث والفرق بين خطوات التمرين والإجراءات المطلوبة في حالة فعلية. |
| [Week_4_Incident_Response_Guide.md](Week_4_Incident_Response_Guide.md) | شرح عملي بالعربي لتجميع الأدلة ومراجعتها وكتابة التقارير وتجهيز عرض الحالة. |

## كود تحليل الإيميل — `email_analyzer/`

| الملف | بيعمل إيه؟ |
| --- | --- |
| [email_parser.py](email_analyzer/email_parser.py) | بيقرأ EML ويفصل الـ Headers والنص وHTML والمرفقات، وبيسجّل نوع الملف من أول بايتاته وحجمه وبصمته وأخطاء القراءة. |
| [header_analyzer.py](email_analyzer/header_analyzer.py) | بيقارن دومينات المرسل والرد والارتداد، بيرتّب مسار `Received`، وبيقرأ نتائج التوثيق من `Authentication-Results`. |
| [analysis_modules.py](email_analyzer/analysis_modules.py) | بيستخرج الروابط والدومينات والـ IPs وعناوين البريد، وبيحسب الخطورة ويفحص VBA بشكل ثابت عند تمرير ملف. |
| [pipeline.py](email_analyzer/pipeline.py) | بيشغّل مراحل التحليل بالترتيب. بيفحص وجهة روابط HTML وبيجمع بيانات العناوين والمرفقات والـ IOCs والدرجة والـ mapping في نفس التقرير. |
| [mitre_mapper.py](email_analyzer/mitre_mapper.py) | بيربط الأدلة بتقنيات MITRE ATT&CK، وبيسجّل السبب والثقة ومصدر الدليل لكل تقنية، مع أسباب استبعاد التقنيات التانية. |
| [make_samples.py](email_analyzer/make_samples.py) | بيولّد العينات التدريبية وبيستبدل نسخ EML الأربعة عند تشغيله. |

### مدخلات التدريب — `email_analyzer/samples/`

| الملف | الغرض منه |
| --- | --- |
| [benign_001.eml](email_analyzer/samples/benign_001.eml) | رسالة سليمة تدريبية للمقارنة مع رسالة التصيّد. |
| [phish_001.eml](email_analyzer/samples/phish_001.eml) | رسالة تصيّد تدريبية لاختبار استخراج مؤشرات الرابط والمرفق والتوثيق. |
| [incomplete_001.eml](email_analyzer/samples/incomplete_001.eml) | رسالة ناقصة لاختبار التعامل مع حقول غير متوفرة. |
| [malformed_001.eml](email_analyzer/samples/malformed_001.eml) | رسالة فيها خلل في البنية لاختبار تسجيل العيب وإكمال التحليل بالبيانات المتاحة. |
| [demo_macro.bas](email_analyzer/samples/demo_macro.bas) | ملف VBA تدريبي مستقل لتجربة الفحص الثابت بالكلمات المفتاحية. |
| [sample_inventory.csv](email_analyzer/samples/sample_inventory.csv) | سجل لأسماء العينات الأربع ومصدرها ونوعها وتاريخ إضافتها. |

### الاختبارات — `email_analyzer/tests/`

| الملف | بيختبر إيه؟ |
| --- | --- |
| [test_email_parser.py](email_analyzer/tests/test_email_parser.py) | قراءة حقول الرسالة وبيانات المرفقات وتوقيعاتها، والتعامل مع الرسائل التالفة أو الملفات المفقودة. |
| [test_header_analyzer.py](email_analyzer/tests/test_header_analyzer.py) | تحليل الـ headers ونتائج التوثيق ومسار الرسالة ومؤشرات اختلاف الدومينات. |
| [test_modules.py](email_analyzer/tests/test_modules.py) | استخراج المؤشرات، وحساب البصمات والدرجة، وتحليل VBA وفك ترميز MIME. |
| [test_pipeline.py](email_analyzer/tests/test_pipeline.py) | تشغيل مسار التحليل على مدخلات مختلفة والتعامل مع روابط تالفة. |
| [test_mitre_mapper.py](email_analyzer/tests/test_mitre_mapper.py) | ربط تقنيات ATT&CK بالأدلة، وحالات الاستبعاد والثقة ومصدر الدليل. |

## أدوات التشغيل وملفات Wazuh

| الملف | بيعمل إيه؟ |
| --- | --- |
| [tools/replay_wazuh.py](tools/replay_wazuh.py) | بيحوّل كل تقرير JSON موجود إلى سطر JSONL ويضيفه لسجل الـ Replay. كل دفعة فيها `run ID` للبحث عن الأحداث المرتبطة في Wazuh. |
| [tools/exercise_response.py](tools/exercise_response.py) | بيشغّل تمرين الأسبوع الثالث على نسخ داخل صندوق بريد محلي. بينقل نسخة الرسالة للحجر، يشيل ملف تجريبي، يسترجع رسالة سليمة من نسخة احتياطية، ويكتب `execution.json`. التمرين الحالي بيعتمد على عينة الحالة المحلية المحددة داخل السكربت. |
| [wazuh/README.md](wazuh/README.md) | خطوات إعداد Windows Agent وLinux Manager، وتشغيل `wazuh-logtest`، والتحقق من Alert في الـ Dashboard. |
| [wazuh/agent-localfile.xml](wazuh/agent-localfile.xml) | مقطع إعداد للـ Windows Agent بيخليه يقرأ سجل JSONL من مسار المشروع. |
| [wazuh/depi_email_rules.xml](wazuh/depi_email_rules.xml) | قواعد الكشف `110210–110216` اللي بتطابق شدة الخطورة والتوثيق والروابط والمرفقات وإشارات الماكرو. |
| [wazuh/rule-test-events.jsonl](wazuh/rule-test-events.jsonl) | 11 حدث اختبار لقواعد Wazuh. كل سطر يمثل حالة مستقلة، وفيه حالات متوقع يظهر لها Alert وحالات مقارنة. |

## التقارير والأدلة — `reports/`

### الأسبوع الأول

| الملف | محتواه |
| --- | --- |
| [Week_1_Phishing_Analysis_Report.md](reports/week_1/Week_1_Phishing_Analysis_Report.md) | تحليل الرسالة التدريبية مع التوثيق والمرفق والرابط والـ IOCs وMITRE. |
| [benign_001.eml.json](reports/week_1/evidence/email/benign_001.eml.json) | تقرير العينة السليمة بدرجة 0 للمقارنة. |
| [phish_001.eml.json](reports/week_1/evidence/email/phish_001.eml.json) | تقرير عينة التصيّد بدرجة 70 وأسبابها، وفيه مؤشرات الرابط والمرفق. |
| [incomplete_001.eml.json](reports/week_1/evidence/email/incomplete_001.eml.json) | تقرير العينة الناقصة، وفيه الحقول الغائبة ونتائج التوثيق غير المعروفة. |
| [malformed_001.eml.json](reports/week_1/evidence/email/malformed_001.eml.json) | تقرير العينة المشوّهة، وفيه وصف عيب بنية الرسالة. |
| [iocs.csv](reports/week_1/evidence/iocs.csv) | جدول المؤشرات المستخرجة، ومصدر كل مؤشر وسبب تسجيله. |
| [macro_analysis.json](reports/week_1/evidence/macro_analysis.json) | نتيجة الفحص الثابت لملف VBA التدريبي المستقل. |
| [pytest-results.txt](reports/week_1/pytest-results.txt) | نتيجة الاختبارات المسجّلة للأسبوع الأول. |

### الأسبوع الثاني

| الملف | محتواه |
| --- | --- |
| [Week_2_Detection_Triage_and_Scope.md](reports/week_2/Week_2_Detection_Triage_and_Scope.md) | فرز التنبيه والتسلسل الزمني والنطاق الأولي للمستخدمين والأجهزة ونتائج اختبار القواعد. |
| [local-replay.jsonl](reports/week_2/evidence/local-replay.jsonl) | أحداث Replay محلية من التقارير التدريبية. |
| [local-rule-check.json](reports/week_2/evidence/local-rule-check.json) | فحص Python محلي لمطابقة حقول JSON مع شروط القاعدة. |
| [agent-replay-2026-11-23.jsonl](reports/week_2/evidence/agent-replay-2026-11-23.jsonl) | نسخة للأحداث اللي اتكتبت في سجل Windows Agent للدفعة الموثّقة. |

### الأسبوع الثالث

| الملف | محتواه |
| --- | --- |
| [Week_3_Incident_Response_Plan.md](reports/week_3/Week_3_Incident_Response_Plan.md) | خطة حفظ الأدلة والاحتواء والتنظيف والاسترجاع وتقييم أثر الحالة، مع نتائج تمرين الصندوق المحلي. |
| [DEPI_Week_3_Chat.md](week3-export-b8dd8d4f302f4ab385d56e6cb2f987fe/DEPI_Week_3_Chat.md) | نسخة محلية مصدّرة من دليل الأسبوع الثالث الموجود كمان في جذر المشروع. |

### الأسبوع الرابع

| الملف | محتواه |
| --- | --- |
| [Final_IR_Case_Report.md](reports/week_4/Final_IR_Case_Report.md) | التقرير الفني النهائي. بيربط التحليل وفرز التنبيه والاستجابة والتحقق، وبيحدد حالة المراجعة والإغلاق. |
| [Executive_Incident_Report.md](reports/week_4/Executive_Incident_Report.md) | ملخص إداري يوضح الحادث، أثره الموثّق، وقرار التعامل والمتابعة. |
| [Forensic_Evidence_Summary.md](reports/week_4/Forensic_Evidence_Summary.md) | ملخص عناصر الأدلة ومصادرها وما تدعمه من استنتاجات. |
| [Chain_of_Custody.md](reports/week_4/Chain_of_Custody.md) | سجل حفظ الأدلة وحيازتها، وفيه معرّفات العناصر والبصمات وأوقات الإجراءات. |
| [Lessons_Learned.md](reports/week_4/Lessons_Learned.md) | الدروس المستفادة والإجراءات المتفق على متابعتها في التمرين. |
| [Updated_IR_Playbook.md](reports/week_4/Updated_IR_Playbook.md) | خطوات الاستجابة لحالات تصيّد مشابهة، ومعايير الفرز والتصعيد والتحقق. |

## ملفات محلية ومخرجات بتظهر أثناء الشغل

| المسار | اللي هتلاقيه فيه |
| --- | --- |
| `samples/` في جذر المشروع | عينات محلية، منها ملفات EML في `benign/` و`phishing/`، ومدخل TXT وعينة VBA وملف CSV محلي. المجلد مستبعد من Git، فمحتواه بيختلف من جهاز للتاني. |
| `reports/generated/` | تقارير JSON من التشغيلات اليدوية، مخرجات الاختبار وأدلة اللاب المحلية. جواه كمان نسخ الشرح المولّدة محليًا. |
| `reports/generated/wazuh-events.jsonl` | سجل الأحداث اللي الـ Agent بيراقبه افتراضيًا. الـ Replay بيضيف أسطر جديدة للسجل. |
| `reports/generated/week3-response-*/` | مخرجات كل تمرين استجابة محلي. `execution.json` بيسجّل نتيجة الخطوات والبصمات، و`incoming/` و`inbox/` و`quarantine/` و`backup/` بتمثل حالات الرسائل والنسخ في التمرين. |
| `reports/generated/week4-evidence-*/` | حزمة التحقيق المحلية. فيها `manifest.json` لفهرسة الأدلة، ونسخة EML وتقرير تحليلها، وسطر الـ Replay، و`wazuh-alert-native.json` للتنبيه الأصلي و`wazuh-alert-observation.json` لملاحظات التحقق. ملفات `case-file-system-triage.json` و`filtered-live-processes.json` بتسجّل نتيجة المراجعة المحدودة، و`reanalysis/` فيه نتائج إعادة التحليل. |
| `reports/generated/word-closeout-*/` | نسخ Word للتسليم وملف ZIP، ومخرجات مراجعة محلية مثل ملفات PDF وصور المعاينة. |
| `docs/` و`screenshots/agent_status/` | مجلدات محلية للتوثيق ولقطات حالة الـ Agent، وبتظهر حاليًا من غير ملفات. |
| `venv/` و`__pycache__/` و`.pytest_cache/` | البيئة المحلية وكاش Python والاختبارات. بيتولدوا من التثبيت والتشغيل. |

ملفات العينات الخاصة وتقارير التشغيل ممكن يكون فيها عناوين بريد وروابط ومعرّفات حساسة. راجعها قبل مشاركة أدلة المشروع، واستخدم العينات التدريبية المدمجة في العرض.
