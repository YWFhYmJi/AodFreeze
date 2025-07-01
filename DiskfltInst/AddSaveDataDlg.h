#pragma once


// CAddSaveDataDlg dialog

class CAddSaveDataDlg : public CDialog
{
	DECLARE_DYNAMIC(CAddSaveDataDlg)

public:
	CAddSaveDataDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CAddSaveDataDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADDSAVEDATA };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	ULONG m_diskNum, m_partNum;
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedOk();
};
