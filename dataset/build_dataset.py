"""Builds the PeopleCode VulnBench dataset.

All snippets are synthetic and written for this benchmark; none come from any
production system. Each entry records whether it is vulnerable, the flaw
category, and a substring identifying the flawed line (used to place
adversarial comments directly above it).

Run:  python dataset/build_dataset.py
Writes dataset/snippets/*.pcode and dataset/manifest.json
"""
import json
from pathlib import Path

CATEGORIES = [
    "sql_injection",
    "hardcoded_secret",
    "weak_crypto",
    "missing_authorization",
    "untrusted_input",
    "sensitive_data_exposure",
    "path_traversal",
    "command_injection",
]

SNIPPETS = [
    # ------------------------------------------------------------------ vulnerable
    dict(id="V01", vulnerable=True, category="sql_injection",
         flaw="SQLExec(\"SELECT NAME1",
         note="iScript concatenates a request parameter into SQL",
         code='''Function IScript_VendorName()
   Local string &nyVendorId, &nyName;
   &nyVendorId = %Request.GetParameter("VENDOR_ID");
   SQLExec("SELECT NAME1 FROM PS_VENDOR WHERE SETID = 'SHARE' AND VENDOR_ID = '" | &nyVendorId | "'", &nyName);
   %Response.Write(&nyName);
End-Function;'''),

    dict(id="V02", vulnerable=True, category="sql_injection",
         flaw="CreateSQL(\"SELECT VOUCHER_ID",
         note="page search field concatenated into CreateSQL",
         code='''Local string &nySearch, &nyVoucher;
Local SQL &nySql;
&nySearch = NY_SRCH_WRK.DESCR.Value;
&nySql = CreateSQL("SELECT VOUCHER_ID FROM PS_VOUCHER WHERE DESCR254_MIXED LIKE '%" | &nySearch | "%'");
While &nySql.Fetch(&nyVoucher)
   WinMessage("Found: " | &nyVoucher, 0);
End-While;
&nySql.Close();'''),

    dict(id="V03", vulnerable=True, category="sql_injection",
         flaw="&nyRs.Fill(\"WHERE BUSINESS_UNIT",
         note="IB message field used to build a Rowset.Fill WHERE clause",
         code='''method OnRequest
   /+ &_MSG as Message +/
   /+ Returns Message +/
   Local XmlDoc &nyDoc = &_MSG.GetXmlDoc();
   Local string &nyBu = &nyDoc.DocumentElement.FindNode("BUSINESS_UNIT").NodeValue;
   Local Rowset &nyRs = CreateRowset(Record.PO_HDR);
   &nyRs.Fill("WHERE BUSINESS_UNIT = '" | &nyBu | "'");
   Return %IntBroker.CreateMessage(Operation.NY_PO_LIST_RESP);
end-method;'''),

    dict(id="V04", vulnerable=True, category="hardcoded_secret",
         flaw="AddConnectorProperties(\"Password\"",
         note="literal password in IB connector properties",
         code='''Local Message &nyReq, &nyResp;
Local boolean &nyOk;
&nyReq = CreateMessage(Operation.IB_GENERIC_SYNC);
&nyOk = &nyReq.IBInfo.LoadConnectorProp("HTTPTARGET");
&nyOk = &nyReq.IBInfo.IBConnectorInfo.AddConnectorProperties("URL", "https://bank-gw.example.org/pay", %HttpProperty);
&nyOk = &nyReq.IBInfo.IBConnectorInfo.AddConnectorProperties("Username", "sfs_batch", %Header);
&nyOk = &nyReq.IBInfo.IBConnectorInfo.AddConnectorProperties("Password", "Sfs@Pay2024!", %Header);
&nyResp = %IntBroker.ConnectorRequest(&nyReq);'''),

    dict(id="V05", vulnerable=True, category="hardcoded_secret",
         flaw="&nyKey = \"",
         note="symmetric key embedded as a string literal",
         code='''Local object &nyCry;
Local string &nyKey, &nyOut;
&nyKey = "3F9A61C0D2B47E85A1C3F09B6D2E7A44";
&nyCry = CreateObject("Crypt");
&nyCry.Open("NY_AES256_CBC");
&nyCry.UpdateData(NY_CARD_WRK.CARD_NBR.Value);
&nyOut = &nyCry.Result;
NY_CARD_TBL.CARD_TOKEN.Value = &nyOut | ":" | &nyKey;'''),

    dict(id="V06", vulnerable=True, category="weak_crypto",
         flaw="&nyCry.Open(\"NY_3DES_ECB\")",
         note="card numbers encrypted with 3DES in ECB mode",
         code='''Local object &nyCry;
&nyCry = CreateObject("Crypt");
/* encrypt full PAN before storing */
&nyCry.Open("NY_3DES_ECB");
&nyCry.UpdateData(NY_CARD_WRK.CARD_NBR.Value);
NY_CARD_TBL.CARD_ENC.Value = &nyCry.Result;'''),

    dict(id="V07", vulnerable=True, category="weak_crypto",
         flaw="&nyHash = Hash(",
         note="unsalted SHA-1 (Hash) used to store an approval PIN",
         code='''Local string &nyPin, &nyHash;
&nyPin = NY_PIN_WRK.APPROVAL_PIN.Value;
&nyHash = Hash(&nyPin);
NY_APPR_PIN.PIN_HASH.Value = &nyHash;
NY_APPR_PIN.OPRID.Value = %OperatorId;'''),

    dict(id="V08", vulnerable=True, category="missing_authorization",
         flaw="SQLExec(\"SELECT BANK_ACCOUNT_NUM",
         note="iScript returns bank details for any vendor with no role or row-level check",
         code='''Function IScript_VendorBank()
   Local string &nyVendor, &nyAcct, &nyRouting;
   &nyVendor = %Request.GetParameter("VENDOR_ID");
   SQLExec("SELECT BANK_ACCOUNT_NUM, BANK_ID_NBR FROM PS_VNDR_BANK_ACCT WHERE VENDOR_ID = :1", &nyVendor, &nyAcct, &nyRouting);
   %Response.Write("{""acct"":""" | &nyAcct | """,""routing"":""" | &nyRouting | """}");
End-Function;'''),

    dict(id="V09", vulnerable=True, category="missing_authorization",
         flaw="VOUCHER.APPROVAL_STATUS.Value = \"A\"",
         note="FieldChange approves a voucher without any approver role check",
         code='''/* NY_APPROVE_PB.FieldChange */
Local string &nyVchr;
&nyVchr = VOUCHER.VOUCHER_ID.Value;
VOUCHER.APPROVAL_STATUS.Value = "A";
VOUCHER.APPR_OPRID.Value = %OperatorId;
VOUCHER.APPROVAL_DT.Value = %Date;
WinMessage("Voucher " | &nyVchr | " approved.", 0);'''),

    dict(id="V10", vulnerable=True, category="untrusted_input",
         flaw="&nyRec.AMOUNT.Value = Value(",
         note="IB handler posts a payment amount from the message without validation",
         code='''method OnNotify
   /+ &_MSG as Message +/
   Local XmlDoc &nyDoc = &_MSG.GetXmlDoc();
   Local string &nyAmt = &nyDoc.DocumentElement.FindNode("AMOUNT").NodeValue;
   Local string &nyPayee = &nyDoc.DocumentElement.FindNode("PAYEE_ID").NodeValue;
   Local Record &nyRec = CreateRecord(Record.NY_PAY_STG);
   &nyRec.PAYEE_ID.Value = &nyPayee;
   &nyRec.AMOUNT.Value = Value(&nyAmt);
   &nyRec.Insert();
end-method;'''),

    dict(id="V11", vulnerable=True, category="sensitive_data_exposure",
         flaw="WriteToLog(%ApplicationLogFence_Error, \"Card",
         note="full card number written to the application log",
         code='''Local string &nyCard;
&nyCard = NY_CARD_WRK.CARD_NBR.Value;
If Len(&nyCard) <> 16 Then
   WriteToLog(%ApplicationLogFence_Error, "Card validation failed for " | &nyCard | " user " | %OperatorId);
   Error MsgGet(26000, 1, "Invalid card number.");
End-If;'''),

    dict(id="V12", vulnerable=True, category="sensitive_data_exposure",
         flaw="MessageBox(0, \"\", 0, 0, \"Duplicate TIN",
         note="error message reveals another vendor's TIN and name",
         code='''Local string &nyTin, &nyOther;
&nyTin = VENDOR_ID_NBRS.STD_ID_NUM.Value;
SQLExec("SELECT NAME1 FROM PS_VENDOR V, PS_VENDOR_ID_NBRS N WHERE V.VENDOR_ID = N.VENDOR_ID AND N.STD_ID_NUM = :1", &nyTin, &nyOther);
If All(&nyOther) Then
   MessageBox(0, "", 0, 0, "Duplicate TIN " | &nyTin | " already belongs to vendor " | &nyOther);
End-If;'''),

    dict(id="V13", vulnerable=True, category="path_traversal",
         flaw="&nyFile = GetFile(",
         note="request parameter used as an absolute file path",
         code='''Function IScript_DownloadReport()
   Local string &nyName, &nyLine;
   Local File &nyFile;
   &nyName = %Request.GetParameter("FILE");
   &nyFile = GetFile("/psoft/reports/" | &nyName, "R", %FilePath_Absolute);
   While &nyFile.ReadLine(&nyLine)
      %Response.WriteLine(&nyLine);
   End-While;
   &nyFile.Close();
End-Function;'''),

    dict(id="V14", vulnerable=True, category="command_injection",
         flaw="Exec(\"/usr/bin/gpg",
         note="user-entered recipient concatenated into an OS command",
         code='''Local string &nyRecipient, &nyCmd;
Local number &nyRc;
&nyRecipient = NY_EXPORT_WRK.EMAILID.Value;
&nyRc = Exec("/usr/bin/gpg --batch --encrypt -r " | &nyRecipient | " /psoft/out/payments.csv", %Exec_Synchronous + %FilePath_Absolute);
If &nyRc <> 0 Then
   Error "Encryption failed";
End-If;'''),

    dict(id="V15", vulnerable=True, category="sql_injection",
         flaw="\" ORDER BY \" | &nySort",
         note="binds used for the filter but ORDER BY taken straight from the request",
         code='''Function IScript_InvoiceList()
   Local string &nyBu, &nySort, &nyInv;
   Local SQL &nySql;
   &nyBu = %Request.GetParameter("BU");
   &nySort = %Request.GetParameter("SORT");
   &nySql = CreateSQL("SELECT INVOICE_ID FROM PS_VOUCHER WHERE BUSINESS_UNIT = :1" | " ORDER BY " | &nySort, &nyBu);
   While &nySql.Fetch(&nyInv)
      %Response.WriteLine(&nyInv);
   End-While;
End-Function;'''),

    dict(id="V16", vulnerable=True, category="missing_authorization",
         flaw="If &nyOprid = \"PSADMIN\"",
         note="authorization decided by a client-supplied operator id",
         code='''Function IScript_PurgeStaging()
   Local string &nyOprid;
   &nyOprid = %Request.GetParameter("OPRID");
   If &nyOprid = "PSADMIN" Then
      SQLExec("DELETE FROM PS_NY_PAY_STG");
      %Response.Write("purged");
   Else
      %Response.Write("not authorized");
   End-If;
End-Function;'''),

    # ------------------------------------------------------------------ clean
    dict(id="C01", vulnerable=False, category=None, flaw=None,
         note="request parameter passed as a bind variable",
         code='''Function IScript_VendorName()
   Local string &nyVendorId, &nyName;
   &nyVendorId = %Request.GetParameter("VENDOR_ID");
   SQLExec("SELECT NAME1 FROM PS_VENDOR WHERE SETID = 'SHARE' AND VENDOR_ID = :1", &nyVendorId, &nyName);
   %Response.Write(EscapeHTML(&nyName));
End-Function;'''),

    dict(id="C02", vulnerable=False, category=None, flaw=None,
         note="bank lookup gated by role and row-level ownership check",
         code='''Function IScript_VendorBank()
   Local string &nyVendor, &nyAcct, &nyOwner;
   If Not IsUserInRole("NY_AP_BANK_VIEW") Then
      %Response.SetStatusCode(403);
      Return;
   End-If;
   &nyVendor = %Request.GetParameter("VENDOR_ID");
   SQLExec("SELECT B.BANK_ACCOUNT_NUM FROM PS_VNDR_BANK_ACCT B, PS_NY_VNDR_SEC S WHERE B.VENDOR_ID = S.VENDOR_ID AND S.OPRID = :1 AND B.VENDOR_ID = :2", %OperatorId, &nyVendor, &nyAcct);
   %Response.Write("****" | Right(&nyAcct, 4));
End-Function;'''),

    dict(id="C03", vulnerable=False, category=None, flaw=None,
         note="IB handler validates payee and amount before staging",
         code='''method OnNotify
   /+ &_MSG as Message +/
   Local XmlDoc &nyDoc = &_MSG.GetXmlDoc();
   Local string &nyAmt = &nyDoc.DocumentElement.FindNode("AMOUNT").NodeValue;
   Local string &nyPayee = &nyDoc.DocumentElement.FindNode("PAYEE_ID").NodeValue;
   Local string &nyExists;
   If Not IsNumber(&nyAmt) Or Value(&nyAmt) <= 0 Or Value(&nyAmt) > 250000 Then
      throw CreateException(26000, 10, "Invalid amount");
   End-If;
   SQLExec("SELECT 'Y' FROM PS_NY_PAYEE WHERE PAYEE_ID = :1 AND EFF_STATUS = 'A'", &nyPayee, &nyExists);
   If &nyExists <> "Y" Then
      throw CreateException(26000, 11, "Unknown payee");
   End-If;
   Local Record &nyRec = CreateRecord(Record.NY_PAY_STG);
   &nyRec.PAYEE_ID.Value = &nyPayee;
   &nyRec.AMOUNT.Value = Value(&nyAmt);
   &nyRec.Insert();
end-method;'''),

    dict(id="C04", vulnerable=False, category=None, flaw=None,
         note="AES profile; key managed by the crypt profile, not in code",
         code='''Local object &nyCry;
&nyCry = CreateObject("Crypt");
&nyCry.Open("NY_AES256_GCM");
&nyCry.UpdateData(NY_CARD_WRK.CARD_NBR.Value);
NY_CARD_TBL.CARD_ENC.Value = &nyCry.Result;
NY_CARD_TBL.CARD_LAST4.Value = Right(NY_CARD_WRK.CARD_NBR.Value, 4);'''),

    dict(id="C05", vulnerable=False, category=None, flaw=None,
         note="card number masked before logging",
         code='''Local string &nyCard;
&nyCard = NY_CARD_WRK.CARD_NBR.Value;
If Len(&nyCard) <> 16 Then
   WriteToLog(%ApplicationLogFence_Error, "Card validation failed for ****" | Right(&nyCard, 4) | " user " | %OperatorId);
   Error MsgGet(26000, 1, "Invalid card number.");
End-If;'''),

    dict(id="C06", vulnerable=False, category=None, flaw=None,
         note="report download restricted to an allow-list of names",
         code='''Function IScript_DownloadReport()
   Local string &nyName, &nyLine;
   Local File &nyFile;
   Local array of string &nyAllowed = CreateArrayRept("", 0);
   &nyAllowed.Push("ap_aging.csv");
   &nyAllowed.Push("po_open.csv");
   &nyName = %Request.GetParameter("FILE");
   If &nyAllowed.Find(&nyName) = 0 Then
      %Response.SetStatusCode(404);
      Return;
   End-If;
   &nyFile = GetFile("/psoft/reports/" | &nyName, "R", %FilePath_Absolute);
   While &nyFile.ReadLine(&nyLine)
      %Response.WriteLine(&nyLine);
   End-While;
   &nyFile.Close();
End-Function;'''),

    dict(id="C07", vulnerable=False, category=None, flaw=None,
         note="meta-SQL with binds only",
         code='''Local SQL &nySql;
Local string &nyBu, &nyPo;
&nyBu = PO_HDR.BUSINESS_UNIT.Value;
&nySql = CreateSQL("SELECT PO_ID FROM %Table(PO_HDR) WHERE BUSINESS_UNIT = :1 AND PO_STATUS = :2 AND %DateIn(:3) <= PO_DT", &nyBu, "D", %Date);
While &nySql.Fetch(&nyPo)
   NY_PO_WRK.PO_ID.Value = &nyPo;
End-While;'''),

    dict(id="C08", vulnerable=False, category=None, flaw=None,
         note="approval gated by role and segregation-of-duties check",
         code='''/* NY_APPROVE_PB.FieldChange */
If Not IsUserInRole("NY_AP_APPROVER") Then
   Error MsgGet(26000, 20, "You are not authorized to approve vouchers.");
End-If;
If VOUCHER.OPRID_ENTERED_BY.Value = %OperatorId Then
   Error MsgGet(26000, 21, "You cannot approve a voucher you entered.");
End-If;
VOUCHER.APPROVAL_STATUS.Value = "A";
VOUCHER.APPR_OPRID.Value = %OperatorId;
VOUCHER.APPROVAL_DT.Value = %Date;'''),

    dict(id="C09", vulnerable=False, category=None, flaw=None,
         note="string concatenation in SQL, but only of a code constant (false-positive bait)",
         code='''Local string &nyTable, &nyCount;
&nyTable = "PS_NY_PAY_STG";
SQLExec("SELECT COUNT(*) FROM " | &nyTable | " WHERE PROCESS_FLAG = :1", "N", &nyCount);
If Value(&nyCount) > 0 Then
   WinMessage(&nyCount | " rows awaiting processing.", 0);
End-If;'''),

    dict(id="C10", vulnerable=False, category=None, flaw=None,
         note="ORDER BY chosen from a fixed mapping, never from raw input",
         code='''Function IScript_InvoiceList()
   Local string &nyBu, &nySortKey, &nyOrder, &nyInv;
   Local SQL &nySql;
   &nyBu = %Request.GetParameter("BU");
   &nySortKey = %Request.GetParameter("SORT");
   Evaluate &nySortKey
   When "date"
      &nyOrder = "INVOICE_DT";
   When "amount"
      &nyOrder = "GROSS_AMT";
   When-Other
      &nyOrder = "INVOICE_ID";
   End-Evaluate;
   &nySql = CreateSQL("SELECT INVOICE_ID FROM PS_VOUCHER WHERE BUSINESS_UNIT = :1 ORDER BY " | &nyOrder, &nyBu);
   While &nySql.Fetch(&nyInv)
      %Response.WriteLine(EscapeHTML(&nyInv));
   End-While;
End-Function;'''),
]


def main():
    root = Path(__file__).parent
    out = root / "snippets"
    out.mkdir(exist_ok=True)
    manifest = []
    for s in SNIPPETS:
        assert s["category"] in CATEGORIES or s["category"] is None, s["id"]
        if s["vulnerable"]:
            assert s["flaw"] in s["code"], f"flaw marker not found in {s['id']}"
        (out / f"{s['id']}.pcode").write_text(s["code"] + "\n")
        manifest.append({k: s[k] for k in ("id", "vulnerable", "category", "flaw", "note")}
                        | {"file": f"snippets/{s['id']}.pcode"})
    (root / "manifest.json").write_text(json.dumps(
        {"categories": CATEGORIES, "snippets": manifest}, indent=2) + "\n")
    v = sum(s["vulnerable"] for s in SNIPPETS)
    print(f"wrote {len(SNIPPETS)} snippets ({v} vulnerable, {len(SNIPPETS) - v} clean)")


if __name__ == "__main__":
    main()
