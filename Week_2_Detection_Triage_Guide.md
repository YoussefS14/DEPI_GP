# Week 2 — Detection, Triage & Scope

في Week 1 بنحلّل الإيميل ونطلع تقرير JSON. في Week 2 بناخد التقرير، نعمله Replay لـ Wazuh عشان يطلع Alert لو شروط القواعد اتحققت، وبعدها بنراجع التنبيه ونحدد نطاق الحالة. الـ Detection بيتم بالكود وWazuh، والـ Triage والـ Scope بيعملهم المحلل بناءً على الأدلة.

| الخطوة | بتتعمل فين؟ | النتيجة |
|---|---|---|
| تجهيز التقرير | Windows | تقرير JSON من Week 1 |
| إعداد الـ Agent | Windows | مراقبة ملف JSONL |
| اختبار القواعد | Linux Manager | تحديد الـ Rule والـ Alert Level |
| التشغيل الفعلي | Windows ثم Dashboard | التحقق من وصول التنبيه عبر الـ Agent |
| Triage وScope | Dashboard وتقرير الحالة | توثيق الأثر وقرار التصعيد |

## 1. جهّز تقرير Week 1

- `phish_001.eml.json` عينة Phishing تجريبية درجتها **70 — High**. التقرير سجّل فشل SPF وDMARC، ولينك وجهته مختلفة عن النص الظاهر، ومرفق بامتداد مزدوج `.pdf.exe`.
- `benign_001.eml.json` عينة سليمة للمقارنة درجتها **0 — Low**. التقرير سجّل مرور SPF وDKIM وDMARC ومفيش لينك أو مرفق اتعلّم كمشبوه.

لو الإيميل جديد، افتح PowerShell داخل `D:\repos\DEPI_GP` وبدّل `new_email.eml` باسم الملف:

```powershell
python main.py "samples\new_email.eml" --output-dir reports/generated
```

الناتج هو `reports/generated/new_email.eml.json`. قيم SPF وDKIM وDMARC جاية من الهيدر زي ما اتسجلت في الإيميل.

## 2. اضبط الـ Windows Agent

دي خطوة إعداد أول مرة أو لما مسار المشروع يتغيّر. ضيف الـ block من `wazuh/agent-localfile.xml` داخل `<ossec_config>` في `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>D:\repos\DEPI_GP\reports\generated\wazuh-events.jsonl</location>
  <log_format>json</log_format>
</localfile>
```

اتأكد إن الملف موجود قبل ما تعيد تشغيل الخدمة. الأوامر دي بتنشئ الملف لو غايب وبتحافظ على السطور الموجودة:

```powershell
New-Item -ItemType Directory -Force reports/generated | Out-Null
if (-not (Test-Path reports/generated/wazuh-events.jsonl)) {
    New-Item -ItemType File reports/generated/wazuh-events.jsonl | Out-Null
}
Restart-Service -Name WazuhSvc
```

شغّل أمر الـ Restart بصلاحية Administrator، واتأكد إن `win11_host` ظاهر **Active**. سكريبت `tools/replay_wazuh.py` بيضيف سطر JSON لكل تقرير فيه الـ Run ID والـ risk score والـ verdict والدومينات وهاشات المرفقات. الـ Agent بيقرأ السطور الجديدة وبيبعتها للـ Manager.

## 3. ثبّت القواعد واختبرها على Linux

ثبّت `wazuh/depi_email_rules.xml` في `/var/ossec/etc/rules/depi_email_rules.xml` على الـ Manager. شغّل فحص الإعدادات وبعد نجاحه افتح اختبار القواعد:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logtest
```

الصق كل سطر JSON من `wazuh/rule-test-events.jsonl` لوحده. **Phase 2** بتعرض فك الـ JSON والحقول. **Phase 3** بتعرض القاعدة ومستوى التنبيه عند المطابقة. العينة المشبوهة المفروض تطابق `110210` بمستوى `10`، والعينة السليمة تتفك كـ JSON من غير DEPI Alert. بعد الاختبار شغّل `sudo systemctl restart wazuh-manager` لتحميل القواعد للتشغيل الفعلي. [توثيق اختبار قواعد Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)

| Rule ID | Level | الشرط |
|---|---:|---|
| `110210` | 10 | `Suspicious` مع `High` |
| `110211` | 7 | `Suspicious` مع `Medium` من غير قاعدة متخصصة |
| `110212` | 5 | `Inconclusive` مع `Low` وSPF وDMARC الاتنين `fail` |
| `110213` | 8 | `Medium` ولينك مشبوه فقط |
| `110214` | 8 | `Medium` ومرفق مشبوه فقط |
| `110215` | 9 | `Medium` ولينك ومرفق مشبوهين |
| `110216` | 9 | `Medium` ومؤشرات Macro من الفحص الساكن |

**الـ `70` درجة الخطورة اللي حسبها الـ Analyzer. الـ `10` مستوى التنبيه اللي حددته قاعدة Wazuh.**

## 4. اعمل Replay وتحقق من الـ Dashboard

من PowerShell داخل فولدر المشروع:

```powershell
python tools/replay_wazuh.py `
  reports/week_1/evidence/email/phish_001.eml.json `
  reports/week_1/evidence/email/benign_001.eml.json
```

1. خُد الـ `Run ID` اللي ظهر مع `Appended 2 event(s)`.
2. افتح **Wazuh → Threat Hunting** وحدد فترة التشغيل. فلتر بـ `rule.id:110210` وبقيمة `data.depi_run_id` اللي طلعت.
3. افتح التنبيه وراجع اسم الـ Agent، وقت التنبيه، واسم التقرير. راجع حقول `data` للـ score والدومين وهاش المرفق.

لو ظهر `Appended` ومفيش Alert، الرسالة بتأكد الكتابة محليًا. راجع إن الـ Agent **Active**، وإن `<localfile>` بيشاور على نفس الملف، وإن القاعدة اتحمّلت بعد الـ Restart. راجع كمان وقت البحث والـ Run ID.

لإيميل جديد شغّل `python tools/replay_wazuh.py reports/generated/new_email.eml.json` وابدأ البحث بالـ **Run ID**. رقم القاعدة بيتحدد من نتيجة التحليل، وممكن الحدث يطلع من غير DEPI Alert.

## 5. اعمل Triage واكتب الـ Timeline والـ Scope

1. **Triage.** راجع التنبيه مع تقرير الإيميل وسجّل سبب التصنيف. في العينة دي اجتماع مؤشرات الهيدر واللينك والمرفق خلّى الحالة تتصنف *simulated phishing*. العينة السليمة للمقارنة ومفيش سبب لتصعيدها.
2. **Timeline.** سجّل وقت الإيميل ومساره من `Date` و`Received`، ثم وقت الـ Replay والـ Alert. في التجربة، توقيت الإيميل من الهيدر التجريبي، ووقت التنبيه من تشغيل اللاب الفعلي.
3. **Scope.** سجّل مين اتستهدف وإيه الأصول اللي ظهرت في الأدلة. `labuser@example.test` هو المستلم المقصود في السيناريو، و`win11_host` هو جهاز اللاب اللي أرسل نتيجة التحليل. التسليم الفعلي والضغط على اللينك وتشغيل المرفق واختراق الحساب غير مؤكدة في الدليل الحالي.
4. **Escalation.** في حالة حقيقية، راجع سجلات البريد للتسليم وانتشار الرسالة، وسجلات الجهاز أو الشبكة لأي فتح أو تشغيل، وسجلات الدخول لأي نشاط مشبوه. النتائج بتحدد قرار التصعيد والاحتواء في Week 3.

## حالة الأدلة في المشروع

- [x] ظهور تنبيه `110210` بمستوى `10` على الـ Dashboard من `win11_host`.
- [x] تحقق النتائج المتوقعة في 11 حالة اختبار على الـ Manager باستخدام `wazuh-logtest`.
- [x] توثيق الـ Triage والـ Timeline والـ Scope.
- [ ] لقطة موسّعة لحقول الـ score والدومين والـ SHA-256 في التنبيه.
- [ ] التحقق من استلام الـ Manager لحدث العينة السليمة لو الـ JSON archives مفعّلة.

التقرير في `reports/week_2/Week_2_Detection_Triage_and_Scope.md`، والأدلة في `reports/week_2/evidence/`، وخطوات إعداد Wazuh في `wazuh/README.md`.

