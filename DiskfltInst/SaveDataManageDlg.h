#pragma once


// CSaveDataManageDlg dialog

class CSaveDataManageDlg : public CDialog
{
	DECLARE_DYNAMIC(CSaveDataManageDlg)

public:
	CSaveDataManageDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CSaveDataManageDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SAVEDATAMANAGE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	CListCtrl m_savedataList;
	afx_msg void OnBnClickedRefreshList();
	afx_msg void OnBnClickedAddSavedata();
	afx_msg void OnBnClickedDeleteSavedata();
};
