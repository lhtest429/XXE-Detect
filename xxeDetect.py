import sys
import os
import zipfile
import shutil

def Detect(path,Content,keyStr,secureStr1,secureStr2,secureStr3):
	if Content.find(keyStr)>-1:
		if Content.find(secureStr1)<=-1 and Content.find(secureStr2)<=-1 and Content.find(secureStr3)<=-1:
			print 'Warning XXE suspective Vul @ '+path+'\nKeyWord is '+keyStr
			print 'please check \n    https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet'
			print 'to repaire the XXE ISSUE\n'

def Controller(path):
	Content = open(path,'r').read()
	#C/C++
	Detect(path,Content,'XercesDOMParser','setCreateEntityReferenceNodes(false)','setCreateEntityReferenceNodes(false)','setCreateEntityReferenceNodes(false)')
	Detect(path,Content,'SAXParser','setDisableDefaultEntityResolution(true)','setDisableDefaultEntityResolution(true)','setDisableDefaultEntityResolution(true)')
	Detect(path,Content,'SAX2XMLReader','fgXercesDisableDefaultEntityResolution','fgXercesDisableDefaultEntityResolution','fgXercesDisableDefaultEntityResolution')

	#JAVA
	Detect(path,Content,'DocumentBuilderFactory.newInstance(','.setfeature(','disallow-doctype-decl','external-general-entities')
	Detect(path,Content,'XMLInputFactory.newInstance(','.setfeature(','SUPPORT_DTD','isSupportingExternalEntities')
	Detect(path,Content,'TransformerFactory.newInstance(','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_STYLESHEET')
	Detect(path,Content,'SchemaFactory.newInstance(','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_SCHEMA')
	Detect(path,Content,'SAXTransformerFactory.newInstance(','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_STYLESHEET')
	Detect(path,Content,'XMLReaderFactory.createXMLReader(','.setfeature(','disallow-doctype-decl','load-external-dtd')
	Detect(path,Content,'SAXReader','disallow-doctype-decl','external-general-entities','external-parameter-entities')

	Detect(path,Content,'SAXParserFactory.newInstance(','external-general-entities','external-parameter-entities','load-external-dtd')
	Detect(path,Content,'DocumentBuilderFactory.newInstance(','ACCESS_EXTERNAL_DTD','ACCESS_EXTERNAL_SCHEMA','')


  
def jieyajar(fullpath,file,jarPath):
	zipFile = zipfile.ZipFile(os.path.join(os.getcwd(), fullpath))
	for fullpath in zipFile.namelist():
		zipFile.extract(fullpath, jarPath+'\\'+file.replace('.jar',''))
	zipFile.close()

#path = sys.argv[1]
#jarPath = sys.argv[2]
path = 'C:\Users\Administrator\Downloads\jartest'
jarPath = 'C:\Users\Administrator\Downloads\jartest\jar'
for dirpath,dirnames,filenames in os.walk(path):
    for file in filenames:
            fullpath=os.path.join(dirpath,file)
            #print fullpath
            if fullpath.find('.jar')>-1:
            	jieyajar(fullpath,file,jarPath)
            else:
            	Controller(fullpath)
for dirpath,dirnames,filenames in os.walk(jarPath):
    for file in filenames:
            fullpath=os.path.join(dirpath,file)
            Controller(fullpath)
shutil.rmtree(jarPath)
