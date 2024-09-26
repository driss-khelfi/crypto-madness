#include "include/OTPMgr.hpp"
#include "include/crypto.hpp"


int main()
{
    OTPMgr::generate_pad(random_seed(), "OTP.bin");

    return 0;
}
