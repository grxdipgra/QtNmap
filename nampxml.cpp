#include "nampxml.h"
#include "qdebug.h"
NMapReader::NMapReader():QXmlStreamReader(){

}

NMapReader::~NMapReader() {

}

bool NMapReader::read(QIODevice *device) {
    QXmlStreamAttributes atributos;
    setDevice(device);
    while (!atEnd()) {
        readNext();
        //qDebug() << "Fuera del while " << name();
        while(readNextStartElement()){
//            if (name() == "nmaprun")
                qDebug() << name();
                qDebug() << attributes().begin()->name();



            //       readXML();
        }
    }















return !error();
}

void NMapReader::readXML() {

    while(readNextStartElement()){
           qDebug() << name();

           qDebug() << readElementText();
           readNext();
           skipCurrentElement();
           if(isEndElement()) break;
           if(isStartElement()) {

       }
}
}

void NMapReader::nmap_scaninfo() {
    while (readNextStartElement()){
  qDebug() << name();
  qDebug() << readElementText();
    }
}

void NMapReader::nmap_host() {
  qDebug() << "hos" << readElementText();
}
void NMapReader::nmap_address() {
  qDebug() << readElementText();
}
void NMapReader::nmap_ports() {
  qDebug() << readElementText();
}
void NMapReader::nmap_times() {
  qDebug() << readElementText();
}
void NMapReader::nmap_runstats() {
  qDebug() << readElementText();
}

