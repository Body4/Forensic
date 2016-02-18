#/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup
import os, py2exe
  
# Ajoute les dépendances
path = os.getcwd() + "\\"
dependencies = [('', [path + 'qt.conf', path + 'icon.png']), 
				('plugins/platforms', [
				path + 'plugins/platforms/qminimal.dll',
				path + 'plugins/platforms/qoffscreen.dll',
				path + 'plugins/platforms/qwindows.dll'])]
				
# Ajoute tous les outils présent dans le dossier 'tools'
for tool in os.listdir(path + "\\tools"):
	f1 = path + '\\tools\\' + tool
	if os.path.isfile(f1):
	#if (os.path.isfile(f1) or os.path.isdir(f1)):
		f2 = 'tools', [f1]
		dependencies.append(f2)
		
# py2exe configuration
# note: les dll_excludes sont supprimées depuis le 'build.bat'
includes = ["sip", "PyQt5.QtCore", "PyQt5.QtGui", "PyQt5.QtWidgets"]

dll_excludes = ["icudt53.dll", "icuin53.dll", "icuuc53.dll", "Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll"]

setup(name="Digital Forensic",
		author="Nicolas Rodrigues, Mathieu Chot-Plassot, Benjamin Dechamps",
		license="GNU General Public License (GPL)",
		data_files=dependencies,
		windows=[{"script":"forensic.py", "icon_resources": [(1, "icon.ico")]}],
		options={"py2exe": {"unbuffered": 1, "compressed": 1, "optimize": 2, "bundle_files": 3,
		"includes": includes, "dll_excludes": dll_excludes}})
