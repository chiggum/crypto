/******************************************************************
DISCRETE LOG MODULO P CALCULATION USING MEET IN MIDDLE ATTACK
*******************************************************************
C++ takes quite a lot of time if input digits are very big (say 150 digits) | Python is very fast for such problem statements
*****************************************************************************************************************************
*Program to compute discrete log modulo a prime p.
Let g be some element in Z∗p and given h in Z∗p such that h=g^x where 1≤x≤2^40 the goal is to find x.

Trivial Brute Force Attack :
*********************************
The trivial algorithm for this problem is to try all 2^40 possible values of x until the correct one is found, that is until we find an x satisfying h=gx in Zp. This requires 240 multiplications. 

Meet in the Middle Attack  :
********************************
Meet in the middle attack runs in time roughly sqrt(2^40) = 2^20.

Let B=2^20. Since x is less than B^2 we can write the unknown x base B as x=x0*B+x1 where x0,x1 are in the range [0,B−1]. Then

    h=g^x=g^(x0*B+x1)=((g^B)^x0)*g^x1   in Zp.

By moving the term g^x1 to the other side we obtain

      h/(g^x1) = (g^B)^x0      in Zp.

The variables in this equation are x0,x1 and everything else is known: we are given g,h and B=2^20. Since the variables x0 and x1 are now on different sides of the equation we can find a solution using meet in the middle:

STEPS:
**************
-First build a hash table of all possible values of the left hand side h/(g^x1) for x1=0,1,…,220.
-Then for each value x0=0,1,2,…,220 check if the right hand side (g^B)^x0 is in this hash table. If so, then we have found a solution (x0,x1) from which we can compute the required x as x=x0*B+x1.

The overall work is about 2^20 multiplications to build the table and another 2^20 lookups in this table. 

******************************/

#include <iostream>
#include <cstdlib>
#include <gmp.h>       // Library for multi precision and modular arithmetic

using namespace std;

unsigned long int isInHash(mpz_t *hash, mpz_t result, unsigned long int count, int checkToReturnValue)
{
    if(count == 0)
        return 1;
    for(unsigned long int i = 0; i < count; ++i)
    {
        if(mpz_cmp(hash[i], result) == 0)
        {
            if(checkToReturnValue == 0)
                return 0;
            else if(checkToReturnValue == 1)
                return 1;
            else 
                return i;
        }
    }
    if(checkToReturnValue == 0)
        return 1;
    else
        return 0;
}

int main (int argc, char **argv) {

    mpz_t p,g,h, count, i, b, rop, base,  inc, result, *hash, *x1;

    mpz_inits(p,g,h,base,inc,rop,count,result,i,hash,x1, NULL);

    mpz_set_str(p, "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171", 10);

    mpz_set_str(g,"11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568", 10); //Decimal base

    mpz_set_str(h, "3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333", 10);

    mpz_set_str(base, "2", 10);

    mpz_set_str(inc, "1", 10);

    mpz_pow_ui(rop, base, 20); 

    mpz_set_str(count, "0", 10);

    unsigned long int temp = 0;

    hash = (mpz_t *)malloc(1 * sizeof(mpz_t));
    x1 = (mpz_t *)malloc(1 * sizeof(mpz_t));

    for(mpz_set_str(i, "0", 10); mpz_cmp(rop, i) >= 0; mpz_add(i, i, inc))
    {
        mpz_powm(result, g, i, p);
        mpz_invert(result, result, p);
        mpz_mul(result, result, h);
        mpz_mod(result, result, p);
        temp = mpz_get_ui(count) ;

        if(isInHash(hash, result, temp, 0))
        {
            mpz_add(count, count, inc);
            temp += 1;

            hash = (mpz_t *)realloc(hash, temp * sizeof(mpz_t));
            x1 = (mpz_t *)realloc(x1, temp * sizeof(mpz_t));

            mpz_init_set(hash[temp - 1], result);
            mpz_init_set(x1[temp - 1], i);
        }
    }

    temp = mpz_get_ui(count);
    unsigned long int reqIndex = 0;

    for(mpz_set_str(i, "0", 10); mpz_cmp(rop, i) >= 0; mpz_add(i, i, inc))
    {
        mpz_mul(result, rop, i);
        mpz_powm(result, g, result, p);

        if(isInHash(hash, result, temp, 1))
        {
            cout << "value of x0 = ";
            mpz_out_str(stdout, 10, i);
            cout << endl;

            reqIndex = isInHash(hash, result, temp, 2);

            cout << "value of x1 = ";
            mpz_out_str(stdout, 10, x1[reqIndex]);
            cout << endl;

            cout << "value of x = ";
            mpz_mul(result, i, rop);
            mpz_add(result, result, x1[reqIndex]);
            mpz_out_str(stdout, 10, result);
            cout << endl;

            break;            
        }
    }
    return 0;
}