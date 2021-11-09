/* testing out payloads. nothing useful here */

char payload[] = "";

int main(void)
{
    int (*dropper)();
    dropper = (int (*)()) payload;
    (int) (*dropper)();
}
