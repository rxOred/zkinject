#include "zkelf.hh"
#include "zkexcept.hh"
#include "zktypes.hh"

/* parser for go specific elf files */
class Go : public Binary::Elf{
    private:
        
    public:
        Go(const char *pathname);
        Shdr *Getgopclntab(void) const;
};
