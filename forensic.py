#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sys import exit, argv
from platform import system, machine
from PyQt5 import QtGui, QtCore, QtWidgets
import ctypes, time, os, sys, tempfile, zipfile
import winreg, win32evtlog, socket, shutil, subprocess

# Indique le chemin du dossier 'plugins', évite d'utiliser le fichier qt.conf
#QtCore.QCoreApplication.addLibraryPath(os.path.join(os.getcwd(), "\\plugins"))


# NOTE: La partie bulk extractor 

# Check OS : Windows only
if system() != 'Windows':
	print("Le programme doit être lancé sur Windows uniquement.")
	exit()
	
# Vérifier si l'utilisateur est admin (uniquement Windows) cu = current user
if ctypes.windll.shell32.IsUserAnAdmin() == 0:
	cu = "(0) Non-Admin"
else:
	cu = "(1) Admin"
	
# Check OS Architecture
if machine() == 'AMD64':
	osarchitecture = 'AMD64'
else:
	osarchitecture = 'x86'


class Forensic(QtCore.QObject):
	# Connect à la barre de progression: envoi les signaux 'emit'
	notifyProgress = QtCore.pyqtSignal(int) # signal progressbar
	finished = QtCore.pyqtSignal() # signal messagebox, end
	cb_bulkextractor = QtCore.pyqtSignal(int) # signal checkbox bulkextractor
	
	def __init__(self, parent = None):
		super(Forensic, self).__init__(parent)
		# Initialisation du dossier temp
		# *utiliser cette variable pour déposer tous les fichiers
		self.tmpdir = tempfile.mkdtemp()
		self.currentuser = os.getlogin()
		self.cb_bulkextractor.connect(self.BulkExt)
		self.StartBulkExt = ''
		
	def __del__(self):
		self.existing = True
		#self.wait()
	
	# Utiliser à l'étape 'archivage' récupère tous les fichiers
	def zipForensic(self, path, ziph):
		parent = os.path.dirname(path)
		contenu = os.walk(path)
		for dirpath, dirs, files in contenu:
			# Inclure les dossiers (meme vide)
			for folder_name in dirs:
				absolute_path = os.path.join(dirpath, folder_name)
				relative_path = absolute_path.replace(parent + '\\', '')
				ziph.write(absolute_path, relative_path)
			# Inclure les fichiers
			for file_name in files:
				absolute_path = os.path.join(dirpath, file_name)
				relative_path = absolute_path.replace(parent + '\\', '')
				ziph.write(absolute_path, relative_path)


	# 
	def WindowsEvent(self, category=None): #System, Application, Security
		def logfilew(filepath, x):
			with open(filepath, 'a', encoding='utf-8', errors='ignore') as f:
				for i in x:
					f.write(i)
					
		try:
			con = win32evtlog.OpenEventLog('localhost',category)
			flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ #trier par date
			max = win32evtlog.GetNumberOfEventLogRecords(con)
			#print(max)
			count = 0
			while 1:
				events = win32evtlog.ReadEventLog(con, flags,0)
				if events:
					for event in events:
						#print('ok')
						data = u"{}".format(event.StringInserts)+"\n"
						winevt = u"{} - Eventid:{} - {} - Eventtype:{} - Eventcategory:{}".format(event.TimeGenerated, event.EventID, event.SourceName, event.EventType, event.EventCategory)+"\n"
						logfilew(self.tmpdir+'\Winevt-{}.log'.format(category), winevt)
						if data:
							logfilew(self.tmpdir+'\Winevt-{}.log'.format(category), data)
						count = count+1
				if count >= max:
					break
		except Exception as e:
			print(e)
			pass

	def GetReg(self, key=None, value=None):
		""" gere l'acces au clés du registre """
		RegKeyHKLM = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
		#RegKeyHKCU = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key)
		#RegKeyHKU = winreg.OpenKey(winreg.HKEY_USERS, key)
		return winreg.QueryValueEx(RegKeyHKLM, value)[0]

	# 
	def logfile(self, filepath, mode, x, lt=None, dict=None):
		with open(filepath, mode, encoding='utf-8', errors='ignore') as f:
			if not dict:
				if lt:
					f.write(x)
				else:
					for i in x:
						f.write(i)
			else:
				for i,j in x.items():
					f.write("{} :    {}".format(i, j)+"\n")	
		
	# Récupère la valeur de la checkbox 'enable bulk'
	def BulkExt(self, state):
		global StartBulkExt
		if state == 1:
			print('Bulk Extractor enabled.')
			self.StartBulkExt = 'ahah'
		else:
			print('Bulk Extractor disabled.')
			self.StartBulkExt = 'ohoh'
			
	
	@QtCore.pyqtSlot()
	def taches(self):
		#print('forensic thread: ', self.thread().currentThreadId())

		# -!- Exécution du dump mémoire :
		if cu[1] == '1':
			self.msg_info = "Exécution du dump mémoire..."
			self.notifyProgress.emit(1)
			if osarchitecture == 'AMD64':
				debuggers = "tools\\Debuggersx64.msi"
			else:
				debuggers = "tools\\Debuggersx86.msi"
				kd = "C:\\Program Files\\Windows Kits\\8.1\\Debuggers\\x86\\windbg.exe"
			subprocess.call("msiexec /i {} /qn".format(debuggers), shell=True)
			time.sleep(15)
			if osarchitecture == 'AMD64':
				kd_1 = "C:\\Program Files (x86)\\Windows Kits\\8.1\\Debuggers\\x64\\windbg.exe"
				kd_2 = "C:\\Program Files\\Windows Kits\\8.1\\Debuggers\\x64\\windbg.exe"
				#print('ok')
				if (os.path.isfile(kd_1)):
					#print('okk')
					args = ["tools\\livekd.exe", '-k', "{}".format(kd_1), '-o', "{}\\Memory.dump".format(self.tmpdir)]
					#livekd = "\\tools\\livekd.exe -o {} -k {}".format(self.tmpdir+"\\Memory.dump",  kd_1)
					#process = subprocess.Popen(livekd, stdout=subprocess.PIPE, creationflags=0x08000000)
					#a = subprocess.Popen([r'tools\\livekd.exe',r'-o {}'.format(self.tmpdir+"\\Memory.dump"),r'-k {}'.format(kd_1)])
					#process.wait()
					subprocess.call(args)
				elif (os.path.isfile(kd_2)):
					args = ["tools\\livekd.exe", '-k', "{}".format(kd_2), '-o', "{}\\Memory.dump".format(self.tmpdir)]
					#livekd = "\\tools\\livekd.exe -o {} -k {}".format(self.tmpdir+"\\Memory.dump",  kd_2)
					#process = subprocess.Popen(livekd, stdout=subprocess.PIPE, creationflags=0x08000000)
					#process.wait()
					#subprocess.Popen([r'tools\\livekd.exe',r'-o {}'.format(self.tmpdir+"\\Memory.dump"),r'-k {}'.format(kd_2)])
					#subprocess.call("tools\\livekd.exe -o {} -k {}".format(self.tmpdir+"\\Memory.dump", kd_2), shell=True)
					subprocess.call(args)
			else:
				args = ["tools\\livekd.exe", '-k', "{}".format(kd), '-o', "{}\\Memory.dump".format(self.tmpdir)]
				subprocess.call(args)
		else:
			print('Dump memory passed (non-admin).')
		
		# -!- Récupération des infos systèmes de base
		self.msg_info = "Récupération des infos systèmes de base..."
		self.notifyProgress.emit(10)
		#recuperation des journaux d'evenements windows
		self.WindowsEvent('System')
		self.WindowsEvent('Software')
		# droit admin requis
		if cu[1] == '1':
			self.WindowsEvent('Security')
		Admin			= self.GetReg(key="SOFTWARE\Microsoft\Windows NT\CurrentVersion", value="RegisteredOwner")
		Windows_ver		= self.GetReg(key="SOFTWARE\Microsoft\Windows NT\CurrentVersion", value="ProductName")
		Arch			= self.GetReg(key="SYSTEM\CurrentControlSet\Control\Session Manager\Environment", value="PROCESSOR_ARCHITECTURE") #AMD64
		Windows_ver2	= self.GetReg(key="SOFTWARE\Microsoft\Windows NT\CurrentVersion", value="CurrentVersion")
		BuildID			= self.GetReg(key="SOFTWARE\Microsoft\Windows NT\CurrentVersion", value="BuildLab")
		IEversion		= self.GetReg(key="SOFTWARE\Microsoft\Internet Explorer", value="Version")
		try: 
			Firefoxversion = self.GetReg(key="SOFTWARE\Mozilla\Mozilla Firefox", value="CurrentVersion")
		except:
			Firefoxversion=None
			pass
		try:
			Chromeversion = self.GetReg(key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\uninstall\\Google Chrome", value="Version")
		except:
			Chromeversion=None
			pass
		Domainname = socket.gethostname() #si pc est dans un domaine affiche FQDN
		Ipaddr = socket.gethostbyname(socket.gethostname())
		listinfo = {"Propriétaire":Admin, "Utilisateur actuel":self.currentuser, "Version de windows":Windows_ver, \
				   "Architecture":Arch, "Noyaux":Windows_ver2,"Build":BuildID, "Version de Firefox":Firefoxversion, \
				   "Version de Internet Explorer":IEversion, "Version de Google Chrome":Chromeversion, "FQDN":Domainname, "Adresse IP":Ipaddr}
		self.logfile(self.tmpdir+'\\infosys.log', 'a', listinfo, dict=True)
		
		
		# -!- connection wmi bdd
		strComputer = "." #localhost
		import win32com.client
		objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
		
		# -!- Récupération des programmes installés
		self.msg_info = "Récupération des programmes installés..."
		self.notifyProgress.emit(15)
		connectWMIServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
		WQuery = connectWMIServices.ExecQuery("SELECT * from Win32_Product")
		for i in WQuery:
			prog = u"{} - {} - {}".format(i.Name, i.Version, i.Installdate)+"\n"
			self.logfile(self.tmpdir+'\\installed_prog.log', 'a', prog, lt=True)
		
		
		# -!- Récupération de tous les services
		#connectWMIServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
		self.msg_info = "Récupération des services..."
		self.notifyProgress.emit(16)
		WQuery = connectWMIServices.ExecQuery("SELECT * FROM Win32_Service")
		for i in WQuery:
			servc = u"service:{} etat:{}".format(i.Caption, i.State)+"\n"
			self.logfile(self.tmpdir+'\\services.log', 'a', servc, lt=True)
				
				
		# -!- Récupération des programmes lancés au demmarage
		#connectWMIServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
		self.msg_info = "Récupération des programmes lancés au demmarage..."
		self.notifyProgress.emit(17)
		WQuery = connectWMIServices.ExecQuery("SELECT * FROM Win32_StartupCommand")
		for i in WQuery:
			sprog = u"commande:{} - location:{} - nom:{} - utilisateur:{}".format(i.Command, i.Location, i.Name, i.User)+"\n"
			self.logfile(self.tmpdir+'\\startup_prog.log','a' , sprog, lt=True)
		
		
		# -!- Récupération de la liste des utilisateurs
		self.msg_info = "Récupération des utilisateurs..."
		self.notifyProgress.emit(18)
		#connectWMIServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
		WQuery = connectWMIServices.ExecQuery("Select * from Win32_UserAccount")
		for i in WQuery:
			user = u"Cet utilisateur s'est deja connectésur le poste: {} - en tant que {}".format(i.Fullname, i.Caption)+"\n"
			self.logfile(self.tmpdir+'\\infosys.log', 'a', user, lt=True)
				
		# -!- Récupération des antivirus installés
		self.msg_info = "Récupération de(s) antivirus installés..."
		self.notifyProgress.emit(20)
		connectWMIServices = objWMIService.ConnectServer(strComputer,"root\SecurityCenter2")
		WQuery = connectWMIServices.ExecQuery("SELECT * FROM AntiVirusProduct")
		for i in WQuery:
			av = u"Antivirus detecte: {}".format(i)+"\n"
			self.logfile(self.tmpdir+'\\infosys.log', 'a', av, lt=True)
				
				
		# -!- Récupération de l'historique de Google Chrome et de Firefox
		self.msg_info = "Récupération de l'historique de google chrome et firefox"
		self.notifyProgress.emit(21)
		if os.path.isdir("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome".format(self.currentuser)):
			shutil.copy2("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History".format(self.currentuser), self.tmpdir+"\\Chrome_history")
		try:
			firefoxpath = [x[0] for x in os.walk("C:\\Users\\{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles".format(self.currentuser))][1]
			if firefoxpath:
				shutil.copy2(firefoxpath+"\\places.sqlite", self.tmpdir+"\\Firefox_history")
		except:
			pass


		# -!- Récupération des fichiers hyberfile.sys et pagefile.sys
		self.msg_info = "Copie de hiberfile.sys et pagefile.sys"
		self.notifyProgress.emit(25)
		try:
			shutil.copy2("C:\\pagefile.sys", self.tmpdir)
			if os.path.isfile("C:\\hiberfile.sys"):
				shutil.copy2("C:\\hiberfile.sys", self.tmpdir)
		except:
			pass
			
		# Bulk extractor
		#if Arch == 'AMD64':
		#	subprocess.call(['tools\\bulk_extractor64.exe','-e', 'all', '-o', self.tmpdir+"\\bulk_extractor", '-R', 'c:\\'])
			#subprocess.Popen(['tools\\bulk_extractor64.exe','-e', 'all', '-o', self.tmpdir+'\\bulk_extractor', '-R', 'c:\\'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		#else:
		#	subprocess.call(['tools\\bulk_extractor32.exe', '-o', self.tmpdir+"\\bulk_extrator", '-R', 'c:\\'])

		
		
		# Archivage
		self.msg_info = "Archivage du dossier temp..."
		self.f_zip = zipfile.ZipFile('Forensic_DataCollected.zip', 'w', zipfile.ZIP_DEFLATED)
		self.zipForensic(self.tmpdir, self.f_zip)
		self.f_zip.close()
		
		# Suppression du dossier temp
		shutil.rmtree(self.tmpdir, ignore_errors=True)
		self.notifyProgress.emit(99)

		# Last action
		self.msg_info = "Terminé."
		self.notifyProgress.emit(100)
		self.finished.emit()

# Redirect stdout to QTextEdit
class EmittingStream(QtCore.QObject):
	textWritten = QtCore.pyqtSignal(str)
	def write(self, text):
		self.textWritten.emit(str(text))
	def flush(self):
		pass

# Box options
class MenuOptions(QtWidgets.QDialog):
	def __init__(self, parent = None):
		super(MenuOptions, self).__init__(parent)
		self.setWindowTitle('Options')
		self.setWindowIcon(QtGui.QIcon('icon.png'))
		self.setFixedSize(200, 150)
		
		import win32api		
		# Libele Drives
		self.libele = QtWidgets.QLabel("Drives: ", self)
		self.libele.move(5, 7)
		self.listeDrives = QtWidgets.QComboBox(self)
		self.listeDrives.move(40, 5)
		drives = win32api.GetLogicalDriveStrings()
		drives = drives.split('\\')
		for i in drives:
			self.listeDrives.addItem(i)
			
		# Enable or disale bulk extractor
		self.bulkExt = QtWidgets.QCheckBox('Enable bulk extractor (très long)', self)
		self.bulkExt.move(5, 30)
		self.bulkExt.stateChanged.connect(self.enableBulkExt)
	def enableBulkExt(self, state):
		be = Forensic()
		if state == 2:
			be.cb_bulkextractor.emit(1)
		else:
			be.cb_bulkextractor.emit(0)
		
		
		#print(type(self.listeDrives.activated[str]))
		#print(str(self.listeDrives.activated[str]))
	
	
	
class MainWindow(QtWidgets.QMainWindow):	
	def __init__(self):
		super().__init__()
		self.setWindowTitle('Digital Forensic')
		self.setWindowIcon(QtGui.QIcon('icon.png'))
		self.setFixedSize(600, 150)
		sys.stdout = EmittingStream(textWritten=self.RedirectOutput)
		#sys.stderr = EmittingStream(textWritten=self.RedirectOutput)
		self.center()
		self.initUI()
	
	def __del__(self):
		sys.stdout = sys.__stdout__
		#sys.stderr = sys.__stderr__
	
	# Calcul le point centre de l'écran
	def center(self):
		frameGm = self.frameGeometry()
		centerPoint = QtWidgets.QDesktopWidget().availableGeometry().center()
		frameGm.moveCenter(centerPoint)
		self.move(frameGm.topLeft())
	
	# Affichage standard
	def initUI(self):
		self.statusBar().showMessage(cu)
		
		# Python Output
		self.boxoutput = QtWidgets.QTextEdit('', self)
		self.boxoutput.setGeometry(120, 70, 365, 55)
		

		# Barre de progression
		self.progress = QtWidgets.QProgressBar(self)
		self.progress.setRange(0, 100)
		self.progress.setGeometry(120, 40, 400, 20)
		
		# Bouton démarrer
		self.btn1 = QtWidgets.QPushButton("Démarrer l'acquisition", self)
		self.btn1.setFixedWidth(120)
		self.btn1.move(2, 4)
		self.btn1.clicked.connect(self.CollectDataStart)
		
		# Bouton Options
		self.btn2 = QtWidgets.QPushButton("Options", self)
		self.btn2.setFixedWidth(70)
		self.btn2.move(125, 4)
		self.btn2.clicked.connect(self.ShowMenuOptions)
		
		# Bouton Quitter
		self.btn3 = QtWidgets.QPushButton("Quitter", self)
		self.btn3.setFixedWidth(70)
		self.btn3.move(520, 4)
		self.btn3.clicked.connect(self.ExitApp)
		#----

		# Connection des actions Forensic à la progressbar
		self.thread = QtCore.QThread()
		self.TachesForensic = Forensic()
		self.TachesForensic.moveToThread(self.thread)
		self.TachesForensic.notifyProgress.connect(self.CollectDataOnProgress)
		#self.connect(self.TachesForensic, SIGNAL("finished()"), self.done)

		self.Options = MenuOptions()
	
		# Affichage de l'UI
		self.show()

	# Exécution de la collecte des données, utilise Forensic
	def CollectDataStart(self):
		self.btn1.setDisabled(True)
		self.btn2.setDisabled(True)
		self.thread.started.connect(self.TachesForensic.taches)
		self.thread.start() #-> def run(self); start thread Forensic()
	
	def CollectDataOnProgress(self, i):
		self.progress.setValue(i)
		self.statusBar().showMessage(cu + " - " + self.TachesForensic.msg_info)
		self.TachesForensic.finished.connect(self.done)
		
	def done(self):
		QtWidgets.QMessageBox.information(self, "Done!", "Acquisition terminée!")
			
	# Show Menu Options
	def ShowMenuOptions(self):
		self.Options.exec_()
	
	# Update textedit with stdout
	def RedirectOutput(self, text):
		cursor = self.boxoutput.textCursor()
		cursor.movePosition(QtGui.QTextCursor.End)
		cursor.insertText(text)
		self.boxoutput.setTextCursor(cursor)
		self.boxoutput.ensureCursorVisible()
		#self.boxoutput.append(text)
		
	def ExitApp(self):
		QtCore.QCoreApplication.instance().quit()
		
if __name__ == '__main__':
	app = QtWidgets.QApplication(argv)
	#print('main thread: ', app.thread().currentThreadId())
	win = MainWindow()
	exit(app.exec_())
