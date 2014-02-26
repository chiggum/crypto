# coding: utf-8
'''
******************************************************************
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

******************************
'''

from gmpy import invert, mpz
     

     
def dlog(p, g, h, B):
    left = { (h*invert(pow(g, x1, p), p)) % p : x1 for x1 in xrange(B) }
    g_b = pow(g, B, p)
    for x0 in xrange(B):
        value = pow(g_b, x0, p)
        if value in left:
            return x0, left[value]
    return None
     
p = input('Enter prime  :  ')
g = input('Enter g      :  ')
h = input('Enter h      :  ')
base = input('Enter base of B : ')
power = input('Enter power of B: ')
p = mpz(p)
g = mpz(g)
h = mpz(h)
B = mpz(base**power)
x = dlog(p, g, h, B)
print 'x0 = ' + str(x[0])
print 'x1 = ' + str(x[1])
print 'x = ' + str((x[0] * B + x[1]))