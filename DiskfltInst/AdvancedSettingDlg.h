#pragma once

typedef struct
{
	UCHAR Flags;
	UCHAR DriverCount;
	UCHAR DriverList[255][32];
	UCHAR ThawSpaceCount;
	WCHAR ThawSpacePath[26][MAX_PATH + 5];
	WCHAR DriverPath[255][MAX_PATH];
} DISKFILTER_ADVANCED_SETTINGS;

// CAdvancedSettingDlg dialog

class CAdvancedSettingDlg : public CDialog
{
	DECLARE_DYNAMIC(CAdvancedSettingDlg)

public:
	CAdvancedSettingDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CAdvancedSettingDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADVSET };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	DISKFILTER_ADVANCED_SETTINGS m_settings;
	afx_msg void OnBnClickedOk();
	afx_msg void OnRclickDriverList(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnRclickThawspaceList(NMHDR *pNMHDR, LRESULT *pResult);
	virtual BOOL OnInitDialog();
	CListCtrl m_driverList;
	afx_msg void OnBnClickedDriverDelsel();
	afx_msg void OnBnClickedDriverAdd();
	afx_msg void OnBnClickedThawspaceAdd();
	afx_msg void OnBnClickedThawspaceDel();
	CListCtrl m_thawspaceList;
	afx_msg void OnBnClickedMountManage();
	afx_msg void OnBnClickedThawspaceSelectall();
	afx_msg void OnBnClickedThawspaceUnhide();
	afx_msg void OnBnClickedThawspaceHide();
	afx_msg void OnBnClickedSavedataManage();
};
