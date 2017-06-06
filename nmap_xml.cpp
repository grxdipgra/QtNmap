#include "nmap_xml.h"
#include "qdebug.h"
#include <QXmlStreamReader>
#include <QTemporaryFile>
#include "QDebug"
#include "QProcess"
#include <QTemporaryFile>



NMap::NMap():QXmlStreamReader(){//Constructor

}

NMap::~NMap() {//Destructor
}

/****************copy_nmapscan*****************************
 * Copia en tmp_nmapscan es el struct NMapScan,
 * donde se guardan todos los datos de la consulta de nmap
 * *******************************************************/

void NMap::copy_nmapscan(NMapScan &tmp_nmapscan) {
   tmp_nmapscan = nmapscan;

}

/*******************************nmap_ejecuta_scan*************************************
 * Realiza el escaneo de equipos y puertos pasados por parametro.
 * El resultado lo guarda en reader, que es de tipo QXmlStreamReader
 ************************************************************************************/
void NMap::nmap_run_scan(QString opciones, QString equipos){
    QTemporaryFile file;
    if (file.open()) {
        QProcess process;
        process.start ("nmap "+opciones+" -oX "+file.fileName() +" "+equipos);
        process.waitForFinished(-1);
        reader.addData(file.readAll());
        file.close();
    }
    readXML();
}

/******************************nmap_num_host_up********************************
 * Devuelve el número de equipos encontrados
 * ***************************************************************************/
int NMap::nmap_num_host_up(){

    return nmapscan.host.count();
}

/***************************nmap_is_open_port_nmapscan************************
 * Devuelve true si el puerto port esta abierto en el equipo pasado por ip
 * Usa nmapscan, es decir necesita haber hecho la busqueda nmap antes
 * **************************************************************************/

bool NMap::nmap_is_open_port_nmapscan (QString ip, QString port){
    int i,j,num_equipos,num_port;
    num_equipos = nmap_num_host_up();
    for (i=0;i<num_equipos;i++){
        num_port = nmapscan.host[i].ports.port.count();
        for (j=0;j<num_port;j++){
        if ((nmapscan.host[i].address.addr == ip) && (nmapscan.host[i].ports.port[j].state.state == "open") && (nmapscan.host[i].ports.port[j].portid == port))
             return true;
        }
    }
return false;
}

/***************************nmap_is_open_port*********************************
 * Devuelve true si el puerto port esta abierto en el equipo pasado por ip
 * Hace la busqueda nmap, es decir no hace falta haber realizado
 * la busqueda nmap antes
 * **************************************************************************/

bool NMap::nmap_is_open_port (QString ip, QString port){

    NMap::nmap_run_scan ("-p "+port,ip);
    NMap::readXML();
    if ((nmapscan.host[0].address.addr == ip) && (nmapscan.host[0].ports.port[0].state.state == "open") && (nmapscan.host[0].ports.port[0].portid == port))
             return true;
return false;
}

/************************nmap_hosts_up***************************************
 * Devuelve el listado de ip's que estan activos en un QList <QString>
 * *************************************************************************/

QList <QString> NMap::nmap_hosts_up(){
    QList  <QString> lista;
    int i,num_equipos;
    num_equipos = nmap_num_host_up();
    for (i=0;i<num_equipos;i++)
        lista.append(nmapscan.host[i].address.addr);
return lista;
}

bool NMap::nmap_is_host_up (QString ip){//Sin hacer

}

bool NMap::is_linux (QString ip){

}

bool NMap::is_win (QString ip){}

bool NMap::is_router (QString ip){}

bool NMap::is_printer (QString ip){
    return nmap_is_open_port_nmapscan(ip,"9100");
}

/*******************************************************************************
 * Metodos auxiliares privados a la clase para meter los datos en el struct
 * ****************************************************************************/

/**********************************readXML**************************************
 * Introduce en cada campo del struct los datos de QXmlStreamReader
 ******************************************************************************/
void NMap::readXML() {
       while(!reader.atEnd()) {
            reader.readNext();
            if (reader.isStartElement()) {
                  if (reader.name() == "nmaprun")
                          nmap_nmaprun();
                  else
                    if(reader.name() == "scaninfo")
                          nmap_scaninfo();
                  else
                    if(reader.name() == "verbose")
                          nmap_verbose();
                  else
                    if(reader.name() == "debuggin")
                          nmap_debuggin();
                  else
                    if(reader.name() == "host")
                          nmap_host();
                  else
                    if(reader.name() == "runstats")
                          nmap_runstats();
            }
         }
    }

void NMap::nmap_nmaprun(){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        QString atributo = attr.name().toString();
        QString valor_tributo = attr.value().toString();
        if (atributo == "scanner" )
            nmapscan.nmaprun.scanner = valor_tributo;
        else
            if (atributo == "args" )
                nmapscan.nmaprun.args = valor_tributo;
            else
                if (atributo == "start" )
                    nmapscan.nmaprun.start = valor_tributo;
                else
                    if (atributo == "startstr" )
                        nmapscan.nmaprun.startstr = valor_tributo;
                    else
                        if (atributo == "version" )
                            nmapscan.nmaprun.version = valor_tributo;
                        else
                            if (atributo == "xmloutputversion" )
                                nmapscan.nmaprun.xmloutputversion = valor_tributo;

    }
}

void NMap::nmap_scaninfo() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        QString atributo = attr.name().toString();
        QString valor_tributo = attr.value().toString();
        if (atributo == "numservices" )
            nmapscan.scaninfo.numservices = atributo.toInt();
        else
            if (atributo == "protocol" )
                nmapscan.scaninfo.protocol = valor_tributo;
            else
                if (atributo == "services" )
                    nmapscan.scaninfo.services = valor_tributo;
                else
                    if (atributo == "type" )
                        nmapscan.scaninfo.type = valor_tributo;
    }
}

void NMap::nmap_verbose() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "level" )
                  nmapscan.debuggin.level = valor_atributo;
    }
}

void NMap::nmap_debuggin() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "level" )
                  nmapscan.debuggin.level = valor_atributo;
    }
}

void NMap::nmap_status(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "state" )
                    host.status.state = valor_atributo;
              else
                if (atributo == "reason" )
                    host.status.reason  = valor_atributo;
              else
                if (atributo == "reason_ttl")
                    host.status.reason_ttl = valor_atributo;
    }
}

void NMap::nmap_address(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "addr" )
                    host.address.addr  = valor_atributo;
              else
                if (atributo == "addrtype")
                    host.address.addrtype = valor_atributo;
    }
}

void NMap::nmap_hostname(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
    }
}

void NMap::nmap_host_host(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
          QString atributo = attr.name().toString();
          QString valor_atributo = attr.value().toString();
          if (atributo == "starttime" )
                  host.starttime = valor_atributo;
          else
              if (atributo == "endtime" )
                  host.endtime = valor_atributo;
    }
}

void NMap::nmap_hosts() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        QString atributo = attr.name().toString();
        QString valor_atributo = attr.value().toString();
        if (atributo == "up" )
            nmapscan.runstats.hosts.up = valor_atributo.toInt();
        else
            if (atributo == "down" )
                nmapscan.runstats.hosts.down = valor_atributo.toInt();
        else
            if (atributo == "total" )
                nmapscan.runstats.hosts.total = valor_atributo.toInt();

    }
}

void NMap::nmap_host() {
     Host host;

     do{
          if (reader.name()=="host")
              nmap_host_host(host);
          else
              if (reader.name()=="status")
                  nmap_status(host);
          else
              if (reader.name()=="address")
                  nmap_address(host);
          else
              if (reader.name()=="hostnames")
                  nmap_hostname(host);
          else
              if (reader.name()=="ports")
                  nmap_ports(host);
          else
              if (reader.name()=="os")
                  nmap_os(host);
          else
              if (reader.name()=="times")
                  nmap_times(host);
          else
              if (reader.name()=="uptime")
                  nmap_uptime(host);
          else
              if (reader.name()=="distance")
                  nmap_distance(host);
          else
              if (reader.name()=="tcpsecuence")
                  nmap_tcpsequence(host);
          else
              if (reader.name()=="ipidsequence")
                  nmap_ipidsequence(host);
          else
              if (reader.name()=="tcptssequence")
                  nmap_tcptssequence(host);

         reader.readNext();

     }
     while (reader.name()!="host");
     nmapscan.host.append(host);


}

void NMap::nmap_ports(Host &host) {
    Port port;
        do{
            if ((!reader.isEndElement()) && (reader.name()!=""))
                nmap_port(port);
            else
                if ((reader.isEndElement())&&(reader.name()=="port"))
                    host.ports.port.append(port);

            if (!reader.atEnd())
                reader.readNext();
            }
        while (reader.name()!="ports");
}

void NMap::nmap_os(Host &host) {
/* OS os;
        do{
            if ((!reader.isEndElement()) && (reader.name()!=""))
                nmap_os_match(os);
            else
                if ((reader.isEndElement())&&(reader.name()=="os"))
                    host.append(os);
            if (!reader.atEnd())
                reader.readNext();
            }
        while (reader.name()!="os");
}*/
}

void NMap::nmap_os_match(OS &os) {
/*
     if (reader.name()=="port"){
         nmap_port_port(port);
         }
     else
        if (reader.name()=="state"){
            nmap_port_state(port);
        }
     else
        if (reader.name()=="service"){
            nmap_port_service(port);
        }
        */
}

void NMap::nmap_port(Port &port) {
     if (reader.name()=="port")
         nmap_port_port(port);
     else
        if (reader.name()=="state")
            nmap_port_state(port);
     else
        if (reader.name()=="service")
            nmap_port_service(port);
}

void NMap::nmap_port_port(Port &port){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        qDebug()<<"nmap_port_port" <<reader.name();
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();

              if (atributo == "protocol")
                     port.protocol= valor_atributo;
              else
                  if (atributo == "portid")
                     port.portid = valor_atributo;
    }
}

void NMap::nmap_port_state(Port &port){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "state")
                     port.state.state = valor_atributo;
              else
                  if (atributo == "reason")
                     port.state.reason = valor_atributo;
              else
                  if (atributo == "reason_ttl")
                     port.state.reason_ttl = valor_atributo;
    }
}

void NMap::nmap_uptime(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "seconds")
                         host.uptime.seconds = valor_atributo;
                  else
                      if (atributo == "lastboot")
                         host.uptime.lastboot = valor_atributo;
        }
}

void NMap::nmap_distance(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "distance")
                         host.distance.value = valor_atributo;
        }
}

void NMap::nmap_tcpsequence(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "index")
                         host.tcpsequence.index = valor_atributo;
                  else
                      if (atributo == "difficulty")
                         host.tcpsequence.difficulty = valor_atributo;
                  else
                      if (atributo == "values")
                         host.tcpsequence.values = valor_atributo;
        }
}

void NMap::nmap_ipidsequence(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "class")
                         host.ipidsecuence.klass = valor_atributo;
                  else
                      if (atributo == "values")
                         host.ipidsecuence.values = valor_atributo;
        }
}

void NMap::nmap_tcptssequence(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "class")
                         host.tcptssequence.klass = valor_atributo;
                  else
                      if (atributo == "values")
                         host.tcptssequence.values = valor_atributo;
        }
}

void NMap::nmap_port_service(Port &port){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "name")
                     port.service.name = valor_atributo;
              else
                  if (atributo == "method")
                     port.service.method = valor_atributo;
              else
                  if (atributo == "conf")
                     port.service.conf = valor_atributo;
     }
}

void NMap::nmap_times(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "srtt")
                     host.times.srtt = valor_atributo;
              else
                  if (atributo == "rttvar")
                     host.times.rttvar = valor_atributo;
              else
                  if (atributo == "to")
                     host.times.to = valor_atributo;
    }
}

void NMap::nmap_runstats() {

    do{
        if (reader.name()=="finished")
            nmap_finished();
        else
            if (reader.name()=="hosts")
                nmap_hosts();
        reader.readNext();
    }
    while (reader.name() != "runstats");

}

void NMap::nmap_finished(){

 foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
    QString atributo = attr.name().toString();
    QString valor_atributo = attr.value().toString();
    if (atributo == "time" )
        nmapscan.runstats.time = valor_atributo;
    else
        if (atributo == "timestr" )
            nmapscan.runstats.timestr = valor_atributo;
    else
        if (atributo == "elapsed" )
            nmapscan.runstats.elapsed = valor_atributo;
    else
        if (atributo == "summary" )
            nmapscan.runstats.summary = valor_atributo;
    else
        if (atributo == "exit" )
            nmapscan.runstats.exit = valor_atributo;
  }
}


