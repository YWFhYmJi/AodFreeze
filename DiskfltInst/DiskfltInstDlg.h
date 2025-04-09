
// DiskfltInstDlg.h : header file
//

#pragma once


// CDiskfltInstDlg dialog
class CDiskfltInstDlg : public CDialog
{
// Construction
public:
	CDiskfltInstDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MAINDLG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;
	CListCtrl	m_volumeList;
	CComboBox	m_command;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOK();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedInstallsys();
	afx_msg void OnBnClickedApply();
	afx_msg void OnItemchangedVolumelist(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedModifypwd();
	afx_msg void OnBnClickedExit();
	afx_msg void OnBnClickedProtectsys();
	afx_msg void OnSelchangeCommand();
	BOOL GetConfigFromControls(PDISKFILTER_PROTECTION_CONFIG Config, ULONGLONG *NeedMemory);
	afx_msg void OnBnClickedAdvancedsetting();
	afx_msg void OnBnClickedCheckupdate();
};

extern BOOL _isDrvInstall;
extern HANDLE _filterDevice;
extern DISKFILTER_PROTECTION_CONFIG _config;
extern CString _password;
extern BOOL _protectEnabled;
extern BOOL _allowDriverLoad;

void SHA256(const PVOID lpData, size_t ulSize, UCHAR lpOutput[32]);
