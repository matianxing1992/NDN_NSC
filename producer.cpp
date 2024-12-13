#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/security/validation-callback.hpp>
#include <ndn-cxx/security/certificate-fetcher-offline.hpp>
#include <boost/asio/io_service.hpp>

#define BOOST_THREAD_PROVIDES_FUTURE
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <thread>
#include <future>
#include <chrono>

#include <functional>
#include <fstream>
#include <string>
#include <iostream>

using namespace ndn;

class rpcProducer
{
public:
    rpcProducer(char *provider, char *service, char *function) : m_face(m_ioService),
                    m_scheduler(m_ioService),
                    PRODUCER_IDENTITY(provider)
    {
        //init result thunks to 0
        resultThunk = 0;
        BASE = PRODUCER_IDENTITY + std::string(service);
        FUNCTION = BASE + std::string(function);
        RESULTS = BASE + std::string("/results/");
    }

    void run()
    {
        std::cerr << "PRODUCER" << std::endl;
        std::cerr << "Attempting to schedule" << std::endl;
        std::cerr << "------------------------" << std::endl;

        // schedule rpcProducer::waitForNotification() to run after 1 nanosecond
        m_scheduler.schedule(1_ns, std::bind(&rpcProducer::waitForNotification, this));


        m_ioService.run();
    }

private:
    //object variables
    boost::asio::io_service m_ioService;
    Face m_face;
    Scheduler m_scheduler;
    KeyChain m_keyChain;
    int resultThunk;
    const double WAIT_TIME_FACTOR = .75;

    //Naming Scheme
    int CONSUMER_NAME_FIELDS = 2;
    std::string PRODUCER_IDENTITY = "/muas/drone1";
    std::string CONSUMER_IDENTITY = "/muas";
    std::string BASE = "/muas/drone1/FlightControl";
    std::string FUNCTION = BASE + "/ManualControl/";
    std::string RESULTS = BASE + "/results/";
    const std::string DELAY_NAME = "delay/";
    const std::string DELIMITER = "/";

    //Results Messages
    const size_t CC_LENGTH = 16;
    const std::string APP_ACK = "APP_ACK";
    const std::string APP_NACK = "APP_NACK";
    const std::string SUCCESS = "GOOD";
    const std::string FAILURE = "BAD";

    //Register prefix to listen for RPC Notifications
    void waitForNotification()
    {
        m_face.registerPrefix(BASE,
                              RegisterPrefixSuccessCallback(),
                              bind(&rpcProducer::onRegisterFailed, this, _1, _2));

        m_face.setInterestFilter(FUNCTION,
                                 bind(&rpcProducer::onNotification, this, _1, _2));
        std::cerr << "REGISTER PREFIX " << BASE << std::endl;
        std::cerr << "LISTENING TO " << FUNCTION << std::endl;
        std::cerr << "------------------------" << std::endl;
    }

    //Received notification of RPC call, acknolwedge and request consumer input
    void onNotification(const InterestFilter &interestFil, const Interest &interest)
    {
        std::cerr << "Received Notification at: " << interestFil.getPrefix() << std::endl;

        if (verifyInterestSignature(interest, CONSUMER_IDENTITY))
        {
            auto data = createData(interest.getName(), APP_ACK, PRODUCER_IDENTITY);
            m_face.put(*data);
            std::string consumerInputParam = extractInterestParam(interest);
            requestConsumerInput(consumerInputParam);

            std::cerr << "Sending response to notification" << std::endl;
            std::cerr << "------------------------" << std::endl;
        }
    }

    //Request Consumer Input based on Parameter in Notification Interest
    void requestConsumerInput(std::string consumerInputParam)
    {
        std::string token = extractRPCCaller(consumerInputParam);
        Interest interest = createInterest(consumerInputParam, true, true);
        addInterestParameterString(RESULTS + token, interest);
        m_keyChain.sign(interest, security::signingByIdentity(Name(PRODUCER_IDENTITY)));
        m_face.expressInterest(interest,
                               bind(&rpcProducer::onConsumerData, this, _1, _2, token),
                               bind(&rpcProducer::onNack, this, _1, _2),
                               bind(&rpcProducer::onTimeout, this, _1));

        std::cerr << "Sending Interest for RPC input " << consumerInputParam << std::endl;
        std::cerr << "------------------------" << std::endl;
    }

    //Receive Input Data from consumer, listen for consumer request for data
    void onConsumerData(const Interest &, const Data &data, std::string token)
    {
        if (verifyDataSignature(data, CONSUMER_IDENTITY))
        {
            std::string dataValue = extractDataValue(data);
            auto fut = boost::async(bind(&rpcProducer::ccCheck, this, dataValue)).share();
            // std::function<void(const Name&, const std::string&)>;
            m_face.setInterestFilter(RESULTS,
                                     bind(&rpcProducer::onResultInterest, this, _1, _2, RESULTS, token, fut),
                                     [](const Name&, const std::string&){std::cerr << "Interest Filter Error" << std::endl;});

            std::cerr << "Successfully fetched input paramaters from consumer" << std::endl;
            std::cerr << dataValue << std::endl;
            std::cerr << "Now listening for " << RESULTS + token << std::endl;
            std::cerr << "------------------------" << std::endl;
        }
    }

    //Consumer requests data, generate and respond with it
    void onResultInterest(const InterestFilter &filterHandle, const Interest &interest, std::string baseName, std::string tokenName, boost::shared_future<bool> fut)
    {
        std::cerr << "Received interest for final results at " << baseName + tokenName << std::endl;
        auto data = createData(interest.getName(), SUCCESS, PRODUCER_IDENTITY);
        m_face.put(*data);
        std::cerr << "------------------------" << std::endl;
    }

    //Requested data finished generating, respond with result
    void sendGeneratedResult(const Interest &interest, boost::shared_future<bool> fut)
    {
        //
        std::cerr << "Received Interest: " << interest.getName().toUri() << std::endl;
        std::string dataValue;
        if (fut.get())
            dataValue = SUCCESS;
        else
            dataValue = FAILURE;
        auto data = createData(interest.getName(), dataValue, PRODUCER_IDENTITY);
        m_face.put(*data);

        std::cerr << "Generated Result, " << dataValue << " , sending" << std::endl;
    }

    //Requested data was still in process, send delay message
    void sendDelayResult(const Interest &interest, std::string baseName, std::string tokenName, boost::shared_future<bool> fut)
    {
        std::string delayedDataName = baseName + DELAY_NAME + tokenName;
        auto data = createData(interest.getName(), APP_NACK + delayedDataName, PRODUCER_IDENTITY);
        m_face.put(*data);
        m_face.setInterestFilter(delayedDataName,
                                 bind(&rpcProducer::onResultInterest, this, _1, _2, baseName + DELAY_NAME, tokenName, fut));

        std::cerr << "Timed out on generating result, sending delay message" << std::endl;
        std::cerr << "Now listening to " << delayedDataName << std::endl;
    }

    //Basic check to verify credit card
    bool ccCheck(std::string inputValue)
    {
        // skip input check
        return true;

        //checks that Credit Card is 16 Digits Long and is all Digits
        if (inputValue.length() != CC_LENGTH || !allStringIsDigit(inputValue))
            return false;

        //Check with Luhn's Algorithms
        if (!luhnAlgo(inputValue))
            return false;

        return true;
    }

    bool allStringIsDigit(std::string inputValue)
    {
        for (size_t i = 0; i < inputValue.length(); i++)
        {
            if (!std::isdigit(inputValue.at(i)))
                return false;
        }
        return true;
    }

    bool luhnAlgo(std::string inputValue)
    {
        //find sum of first 15 numbers according to luhns
        int sum = 0;
        for (size_t i = 0; i < inputValue.length() - 1; i++)
        {
            int x = inputValue.at(i) - '0';
            if (i % 2 == 0)
            {
                x *= 2;
                if (x >= 10)
                    x = (x / 10) + (x % 10);
            }
            sum += x;
        }
        //check first 15 sum + check number is divisble by 10 with no remainder
        if (((sum + (inputValue.at(inputValue.length() - 1) - '0')) % 10) == 0)
            return true;
        else
            return false;
    }

    //extract Interest Parameter as String
    std::string extractInterestParam(const Interest &interest)
    {
        //std::string interestParam(reinterpret_cast<const char *>(interest.getApplicationParameters().value()));
        return ndn::readString(interest.getApplicationParameters());
    }

    //extract Interest Parameter as String
    std::string extractDataValue(const Data &data)
    {
        std::string dataValue(reinterpret_cast<const char *>(data.getContent().value()));
        return dataValue;
    }

    //extract the client token + RPC number to be used in generating result name
    std::string extractRPCCaller(std::string consumerRPCInput)
    {
        std::size_t found = 0;
        for (int i = 0; i <= CONSUMER_NAME_FIELDS; i++)
        {
            found = consumerRPCInput.find(DELIMITER, found);
            found++;
        }
        std::string token = consumerRPCInput.substr(1, found - 1);
        return token + std::to_string(++resultThunk);
    }

    //create an Interest packet with specified values
    Interest createInterest(std::string name, bool canBePrefix, bool mustBeFresh)
    {
        Name interestName(name);
        Interest interest(interestName);
        interest.setCanBePrefix(canBePrefix);
        interest.setMustBeFresh(mustBeFresh);

        return interest;
    }

    //Add a string as an Interest Parameter
    void addInterestParameterString(std::string params, Interest &interest)
    {
        //const uint8_t *params_uint = reinterpret_cast<const uint8_t *>(&params[0]);
        //interest.setApplicationParameters(params_uint, params.length() + 1);

        // set application parameters using params
        interest.setApplicationParameters(ndn::makeStringBlock(ndn::tlv::ApplicationParameters,params));
    }

    //Retrieves Key for a specific identity
    ndn::security::pib::Key getKeyForIdentity(std::string identity)
    {
        const auto &pib = m_keyChain.getPib();
        const auto &verifyIdentity = pib.getIdentity(Name(identity));
        return verifyIdentity.getDefaultKey();
    }

    //Signature Verification Functions for Interest
    bool verifyInterestSignature(const Interest &interest, std::string identity)
    {
        //skip verification because NDN_NSC does have a good API for mulitiple identities
        return true;

        if (security::verifySignature(interest, getKeyForIdentity(identity)))
        {
            std::cerr << "Interest Signature - Verified" << std::endl;
            return true;
        }
        else
        {
            std::cerr << "Interest Signature - ERROR, can't verify" << std::endl;
            return false;
        }
    }

    //Signature Verification Functions for Data
    bool verifyDataSignature(const Data &data, std::string identity)
    {
        //skip verification because NDN_NSC does have a good API for mulitiple identities
        return true;

        if (security::verifySignature(data, getKeyForIdentity(identity)))
        {
            std::cerr << "Data Signature - Verified" << std::endl;
            return true;
        }
        else
        {
            std::cerr << "Data Signature - ERROR, can't verify" << std::endl;
            return false;
        }
    }

    //create a Data packet with specified values
    std::shared_ptr<ndn::Data> createData(const ndn::Name dataName, std::string content, std::string identity)
    {
        auto data = make_shared<Data>(dataName);
        data->setFreshnessPeriod(4000_ms);
        //data->setContent(reinterpret_cast<const uint8_t *>(content.c_str()), content.length() + 1);
        // set content of data using content
        data->setContent(ndn::makeStringBlock(ndn::tlv::Content,content));
        m_keyChain.sign(*data, signingByIdentity(identity));

        return data;
    }

    //Boilerplate NACK, Timeout, Failure to Register
    void onNack(const Interest &, const lp::Nack &nack) const
    {
        std::cerr << "Received Nack with reason " << nack.getReason() << std::endl;
        std::cerr << "------------------------" << std::endl;
    }

    void onTimeout(const Interest &interest) const
    {
        std::cerr << "Timeout for " << interest << std::endl;
        std::cerr << "------------------------" << std::endl;
    }

    void onRegisterFailed(const Name &prefix, const std::string &reason)
    {
        std::cerr << "ERROR: Failed to register prefix '" << prefix
                  << "' with the local forwarder (" << reason << ")" << std::endl;
        std::cerr << "------------------------" << std::endl;
        m_face.shutdown();
    }
};

int main(int argc, char **argv)
{
    try
    {
        if (argc != 4)
        {
            std::cerr << "Usage: ./producer <provider> <service> <function>" << std::endl;
            exit(1);
        }
        rpcProducer producer(argv[1], argv[2], argv[3]);
        producer.run();
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        std::cerr << "------------------------" << std::endl;
        return 1;
    }
}