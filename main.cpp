#include "nmap_xml.h"
#include <QApplication>
#include "QDebug"
#include "QProcess"
#include <QTemporaryFile>
#include <qstring.h>


int main(int argc, char *argv[])
{
    QString opciones = "-p 22,8080,78,66,55,33";
    QString equipos = "10.7.15.224";
    int num_equipos,i,j,num_port;
    NMap* nmap = new NMap();
    NMapScan NmapScan;

    nmap->nmap_run_scan(opciones,equipos);
    //nmap->readXML();
    nmap->copy_nmapscan(NmapScan);




    qDebug () << nmap->nmap_hosts_up();
    //num_equipos = nmap->nmap_num_host_up();
    num_equipos = nmap->nmap_num_host_up();
    //qDebug() << nmap->nmap_is_open_port_nmapscan("10.100.251.2", "22");
    //qDebug() << nmap->nmap_is_open_port("10.100.251.25", "83");

    //qDebug() << "debuggin level " << NmapScan.host[0].status.state;
    for (i=0;i<num_equipos;i++){
        qDebug()<< "Status" <<  NmapScan.host[i].status.state;
        qDebug()<< "address" <<  NmapScan.host[i].address.addr;
        qDebug()<< "Puertos escaneados" <<  NmapScan.host[i].ports.port.count();
        num_port = NmapScan.host[i].ports.port.count();
        for (j=0;j<num_port;j++){
        qDebug()<< "portid" <<  NmapScan.host[i].ports.port[j].portid;
        qDebug()<< "state" <<  NmapScan.host[i].ports.port[j].state.state;
        }
    }
}



   /* qDebug()<< consulta.scaninfo.services;
    qDebug()<< consulta.runstats.summary;
    qDebug()<< consulta.runstats.timestr;
    qDebug()<<"dd"<< consulta.host.first().starttime;
    qDebug()<<"address"<< consulta.host.first().address.addr;
    qDebug()<<"dd"<< consulta.host.first().starttime;
    qDebug()<< consulta.runstats.timestr;
*/


