#pragma once


// CAddMountDlg dialog

class CAddMountDlg : public CDialog
{
	DECLARE_DYNAMIC(CAddMountDlg)

public:
	CAddMountDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CAddMountDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADDMOUNT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	WCHAR m_volumeLetter;
	ULONG m_diskNum, m_partNum;
	BOOL m_readOnly;
	afx_msg void OnBnClickedOk();
	virtual BOOL OnInitDialog();
};
