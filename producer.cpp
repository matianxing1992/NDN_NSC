#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/v2/validator.hpp>
#include <ndn-cxx/security/v2/validation-callback.hpp>
#include <ndn-cxx/security/v2/certificate-fetcher-offline.hpp>
#include <ndn-cxx/signature-info.hpp>
#include <ndn-cxx/key-locator.hpp>
#include <ndn-cxx/detail/cancel-handle.hpp>
#include <boost/asio/io_service.hpp>

#define BOOST_THREAD_PROVIDES_FUTURE
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
// #include <boost/fiber/future/async.hpp>
// #include <boost/fiber/future/future.hpp>
#include <thread>
#include <future>
#include <chrono>

#include <functional>
#include <fstream>
#include <string>
#include <iostream>

using namespace ndn;

class Producer
{
public:
    Producer() : m_face(m_ioService),
                 m_scheduler(m_ioService)
    {
        resultThunk = 0;
    }

    void run()
    {
        std::cerr << "PRODUCER" << std::endl;
        std::cerr << "Attempting to schedule" << std::endl;
        std::cerr << "------------------------" << std::endl;
        m_scheduler.schedule(1_ns, bind(&Producer::waitForNotification, this));
        m_ioService.run();
    }

private:
    boost::asio::io_service m_ioService;
    Face m_face;
    Scheduler m_scheduler;
    KeyChain m_keyChain;
    int resultThunk;
    int DEVICE_NAME_FIELDS = 2;
    const std::string DAN_IDENTITY = "/daniel";
    const std::string BASE = "/eshop/cardchecker";
    const std::string FUNCTION = BASE + "/function/";
    const std::string RESULTS = BASE + "/results/";
    const std::string DELIMITER = "/";

    //Register prefix to listen for RPC Notifications
    void waitForNotification()
    {
        m_face.registerPrefix(BASE,
                              RegisterPrefixSuccessCallback(),
                              bind(&Producer::onRegisterFailed, this, _1, _2));

        m_face.setInterestFilter(FUNCTION,
                                 bind(&Producer::onNotification, this, _1, _2));
        std::cerr << "REGISTER PREFIX " << BASE << std::endl;
        std::cerr << "LISTENING TO " << FUNCTION << std::endl;
        std::cerr << "------------------------" << std::endl;
    }

    //Received notification of RPC call, acknolwedge and request consumer input
    void onNotification(const InterestFilter &, const Interest &interest)
    {
        std::cerr << "Received Notification:\n"
                  << interest.getName() << std::endl;

        const auto &pib = m_keyChain.getPib();
        const auto &identity = pib.getIdentity(Name("/pos/device1"));
        if (security::verifySignature(interest, identity.getDefaultKey()))
            std::cerr << "interest signature verified" << std::endl;
        else
            std::cerr << "can't verify interest signature" << std::endl;

        auto data = createData(interest.getName(), "ACK NOTIFICATION", DAN_IDENTITY);
        m_face.put(*data);
        std::cerr << "Sending response to notification" << std::endl;
        std::cerr << "------------------------" << std::endl;

        std::string consumerInputParam = extractInterestParam(interest);
        requestConsumerInput(consumerInputParam);
    }

    //Request Consumer Input based on Parameter in Notification Interest
    void requestConsumerInput(std::string consumerInputParam)
    {
        std::string token = extractRPCCaller(consumerInputParam);

        Interest interest = createInterest(consumerInputParam, true, true);
        addInterestParameterString(RESULTS + token, interest);
        m_keyChain.sign(interest, security::signingByIdentity(Name(DAN_IDENTITY)));

        std::cerr << "Sending Interest for CC Number " << interest << std::endl;
        std::cerr << "------------------------" << std::endl;
        m_face.expressInterest(interest,
                               bind(&Producer::onConsumerData, this, _1, _2, token),
                               bind(&Producer::onNack, this, _1, _2),
                               bind(&Producer::onTimeout, this, _1));
    }

    //Receive Input Data from consumer, listen for consumer request for data
    void onConsumerData(const Interest &, const Data &data, std::string token)
    {
        namespace ndnsec = ndn::security::v2;
        ndnsec::Validator validator(make_unique<ndnsec::ValidationPolicyConfig>(), make_unique<ndnsec::CertificateFetcherOffline>());
        auto &config = static_cast<ndnsec::ValidationPolicyConfig &>(validator.getPolicy());
        config.load("schema.conf");
        validator.validate(
            data,
            [this](auto data) {
                std::cout << "ValidatorConfig::NICE. Command Interest has a valid signature" << std::endl;
            },
            [](auto v, auto error) {
                std::cout << "Error is " << error.getInfo() << std::endl;
            });

        std::string dataValue = extractDataValue(data);
        m_face.setInterestFilter(RESULTS + token,
                                 bind(&Producer::onResultInterest, this, _1, _2, dataValue));

        std::cerr << "Successfully fetched input paramaters from consumer" << std::endl;
        std::cerr << dataValue << std::endl;
        std::cerr << "Now listening for " << RESULTS + token << std::endl;
        std::cerr << "------------------------" << std::endl;
    }

    //Consumer requests data, generate and respond with it
    void onResultInterest(const InterestFilter &filterHandle, const Interest &interest, std::string inputValue)
    {
        std::cerr << "Received Consumer Interest for Final Result:" << std::endl;
        std::cerr << interest.getName() << std::endl;
        std::cerr << "Consumer Interest Lifetime is " << std::endl;
        std::cerr << interest.getInterestLifetime().count() << std::endl;
        std::cerr << "Will wait 75 percent of that time before defferring: " << std::endl;
        std::cerr << interest.getInterestLifetime().count() * 0.75 << std::endl;

        boost::future<bool> fut = boost::async(bind(&Producer::ccCheck, this, inputValue));
        auto waitTime = interest.getInterestLifetime().count();
        waitTime *= .75;
        if (fut.wait_for(boost::chrono::milliseconds(waitTime)) == boost::future_status::ready)
        {
            auto data = createData(interest.getName(), "GOOD", DAN_IDENTITY);
            m_face.put(*data);
        }
        else
        {
            std::cerr << "TIMING OUT" << std::endl;
            auto data = createData(interest.getName(), "TIME OUT", DAN_IDENTITY);
            m_face.put(*data);
        }

        std::cerr << "------------------------" << std::endl;
    }

    bool ccCheck(std::string inputValue)
    {
        sleep(10);
        std::cerr << "FINISHED SLEEP" << std::endl;
        return true;
    }

    //extract Interest Parameter as String
    std::string extractInterestParam(const Interest &interest)
    {
        std::string interestParam(reinterpret_cast<const char *>(interest.getApplicationParameters().value()));
        return interestParam;
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
        for (int i = 0; i <= DEVICE_NAME_FIELDS; i++)
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
        const uint8_t *params_uint = reinterpret_cast<const uint8_t *>(&params[0]);
        interest.setApplicationParameters(params_uint, params.length() + 1);
    }

    //create a Data packet with specified values
    std::shared_ptr<ndn::Data> createData(const ndn::Name dataName, std::string content, std::string identity)
    {
        auto data = make_shared<Data>(dataName);
        data->setFreshnessPeriod(5_ms);
        data->setContent(reinterpret_cast<const uint8_t *>(content.c_str()), content.length() + 1);
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
        Producer producer;
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