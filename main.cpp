#include <vector>
#include <tins/tins.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <pthread.h>
#include <iomanip>
#include <stdlib.h>
using namespace Tins;


class apinfo{
public:
    void printing()
    {
        std::cout<<"@"<<std::setw(10)<<this->bssid<<std::setw(10)<<this->power<<std::setw(10)<<this->beacon<<this->data<<std::setw(10)<<this->channel<<std::setw(20)<<this->essid<<std::endl;
    }

    int power;
    int beacon=0;
    std::string bssid;
    int channel;
    std::string essid;
    int data=0;
};

class station{
public:
    void printing()
    {
        std::cout<<"#"<<std::setw(25)<<this->bssid<<std::setw(25)<<mac<<std::setw(10)<<probe<<std::endl;
    }

    std::string bssid;
    std::string mac;
    std::string probe;

};
pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;


void beacon_plus(std::string mac,std::vector<apinfo>& apVector )
{
    pthread_mutex_lock(&mutex);

    for(std::vector<apinfo>::iterator it=apVector.begin();it!=apVector.end();it++)
    {
        if(it->bssid ==mac)
        {
            it->beacon=it->beacon+1;
        }
    }
    pthread_mutex_unlock(&mutex);



}


void data_plus(std::string mac,std::vector<apinfo>& apVector )
{

    for(std::vector<apinfo>::iterator it=apVector.begin();it!=apVector.end();it++)
    {
        if(it->bssid ==mac)
        {
            it->data=it->data+1;
        }
    }


}

bool update;

std::vector<apinfo> apVector;
std::vector<station> stationVector;

template <typename T>
void stationVector_plus(std::vector<T>& bssid, std::string apmac, std::string stationmac)
{
    bssid.push_back(stationmac);
        station sta;
        sta.bssid=apmac;
        sta.mac=stationmac;

        pthread_mutex_lock(&mutex);

        stationVector.push_back(sta);
        update=true;

        pthread_mutex_unlock(&mutex);

}


template <typename T>
void apVector_plus(std::vector<T>& bssid, std::string mac, Dot11ManagementFrame* dot11,RadioTap* radiotap)
{
        bssid.push_back(mac);
        apinfo ap;
        ap.bssid=dot11->addr2().to_string();
        ap.channel=radiotap->channel_freq() % 2412 / 5 + 1;
        std::string tempssid= dot11->ssid();
            if(!tempssid.empty())
                ap.essid=dot11->ssid();
            else
                ap.essid="empty";
        ap.power =radiotap->dbm_signal();

        pthread_mutex_lock(&mutex);

        apVector.push_back(ap);
        update=true;

        pthread_mutex_unlock(&mutex);

}


std::vector<Packet> vt;


void* print(void* data)
{

    while(1){
        pthread_mutex_lock(&mutex);
    if(update)
    {
        system("clear");
        std::cout<<"\t\t ap list"<<std::endl;
        int apsize=apVector.size();
        int stasize=stationVector.size();

        for(int i=0;i<apsize;i++)
            apVector[i].printing();

        std::cout<<"\t\t\ station list"<<std::endl;
        for(int i=0;i<stasize;i++)
            stationVector[i].printing();

        update=false;
    }

    pthread_mutex_unlock(&mutex);
    }
}
PDU* pdu;

int main() {

    pthread_t p_thread1;
    int thr_id;
    thr_id=pthread_create(&p_thread1,NULL,print,NULL);

    std::vector<std::string> essid;
    std::vector<std::string> bssid;
    std::vector<std::string>::iterator strit;
    std::vector<std::string> stationMac;



    std::vector<Packet>::iterator it=vt.begin();

    while(vt.size() < 10)
    {
        Sniffer sniffer("mon0");
      //  sniffer.set_filter("type mgt");
        vt.push_back(sniffer.next_packet());
    }

    int i=0;
    //for(it=vt.begin();it!=vt.end();it++)
    for(;;)
    {
        Sniffer sniffer("mon0");
      //  sniffer.set_filter("type mgt");
        vt.push_back(sniffer.next_packet());
        pdu = vt[i].pdu();
        i++;

        RadioTap* temp = pdu->find_pdu<RadioTap>();
        if (temp == nullptr)
        {

           pdu= vt[i+1].pdu();
            continue;
        }




        Dot11ManagementFrame* dot11 = (Dot11ManagementFrame*)temp->find_pdu<Dot11ManagementFrame>();
        if( dot11 != nullptr)
        {
            auto subtype = dot11->subtype();
        std::string strtemp=dot11->addr2().to_string();


//        if(!strtemp.empty())
//        std::cout<< dot11->ssid() <<std::endl;
//        else
//           std::cout<<"empty ssid"<<std::endl;

//        std::cout<< dot11->addr1() <<std::endl;
//        std::cout<< dot11->addr2() <<std::endl;
//        std::cout<< dot11->addr3() <<std::endl;
//        std::cout<< dot11->addr4() <<std::endl;

//        std::cout<< std::endl;


        beacon_plus(dot11->addr2().to_string(),apVector);

        strit= find(bssid.begin(),bssid.end(),strtemp);
        if(strit == bssid.end())
           apVector_plus(bssid,strtemp,dot11,temp);
//        {
//            bssid.push_back(strtemp);
//            apinfo ap;
//            ap.bssid=dot11->addr2().to_string();
//            ap.channel=temp->channel_freq() % 2412 / 5 + 1;
//            auto tempssid= dot11->ssid();
//                if(!tempssid.empty())
//                    ap.essid=dot11->ssid();
//                else
//                    ap.essid="empty";
//            ap.power =temp->dbm_signal();

//            pthread_mutex_lock(&mutex);

//            apVector.push_back(ap);
//            update=true;

//            pthread_mutex_unlock(&mutex);

//        }
            if(subtype == Dot11::PROBE_REQ)
            {
                Dot11ProbeRequest* p_req = (Dot11ProbeRequest*)dot11->find_pdu<Dot11ProbeRequest>();

                std::string apmac = p_req->addr1().to_string();
                std::string stationmac=p_req->addr2().to_string();

                std::vector<std::string>::iterator stat= find(stationMac.begin(),stationMac.end(),stationmac);
                if(stat == stationMac.end())
                stationVector_plus(stationMac,apmac,stationmac);
//                std::cout<<"#" <<p_req->addr1() <<std::endl; bssid
//                std::cout<<"#" <<p_req->addr2() <<std::endl; station
//                std::cout<<"#" <<p_req->addr3() <<std::endl;
//                std::cout<<"#" <<p_req->addr4() <<std::endl;


            }
            else if(subtype == Dot11::PROBE_RESP)
            {
                Dot11ProbeResponse* p_resp = (Dot11ProbeResponse*)dot11->find_pdu<Dot11ProbeResponse>();

                std::string apmac = p_resp->addr2().to_string();
                std::string stationmac=p_resp->addr1().to_string();

                std::vector<std::string>::iterator stat= find(stationMac.begin(),stationMac.end(),stationmac);
                if(stat == stationMac.end())
                stationVector_plus(stationMac,apmac,stationmac);
//


//                std::cout<<"@" <<p_resp->addr1() <<std::endl;   //station
//                std::cout<<"@" <<p_resp->addr2() <<std::endl;   //bssid

//                std::cout<<"@" <<p_resp->addr3() <<std::endl;
//                std::cout<<"@" <<p_resp->addr4() <<std::endl;

            }
        }
        else
        {
            Dot11Data* dot11data = (Dot11Data*)temp->find_pdu<Dot11Data>();
            if(dot11data == nullptr)
                continue;

            std::string apmac=dot11data->addr2().to_string();
            std::string stationmac=dot11data->addr1().to_string();

            pthread_mutex_lock(&mutex);

            data_plus(dot11data->addr2().to_string(),apVector);

            pthread_mutex_unlock(&mutex);


            strit= find(bssid.begin(),bssid.end(),apmac);
            if(strit == bssid.end())
                apVector_plus(bssid,apmac,dot11,temp);
//            {
//                bssid.push_back(apmac);
//                apinfo ap;
//                ap.bssid=apmac;
//                ap.channel=temp->channel_freq() % 2412 / 5 + 1;
//                ap.essid=dot11->ssid();
//                ap.power =temp->dbm_signal();

//                pthread_mutex_lock(&mutex);

//                apVector.push_back(ap);

//                pthread_mutex_unlock(&mutex);

//            }

            std::vector<std::string>::iterator stat= find(stationMac.begin(),stationMac.end(),stationmac);
            if(stat == stationMac.end())
            stationVector_plus(stationMac,apmac,stationmac);
//            {
//                stationMac.push_back(stationmac);
//                station sta;
//                sta.bssid=apmac;
//                sta.mac=stationmac;

//                pthread_mutex_lock(&mutex);

//                stationVector.push_back(sta);

//                pthread_mutex_unlock(&mutex);

//            }


            std::cout<< dot11data->addr1() <<std::endl;//station
            std::cout<< dot11data->addr2() <<std::endl;//ap
        }


//        pthread_mutex_lock(&mutex);
//        vt.erase(it);
//        pthread_mutex_unlock(&mutex);

    }
    int status;
    pthread_join(p_thread1, (void **)&status);
    return 0;


}
