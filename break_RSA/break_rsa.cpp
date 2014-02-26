#include <iostream>
#include <cstdio>
#include <gmp.h>
#include <cmath>

using namespace std;

int main()
{
	mpz_t n, a, p, q, rt, x;
	mpz_inits(n, a, p, q, rt, x, NULL);

	#if 0
	mpz_set_str(n, "179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581", 10);

	mpz_sqrt(rt, n);
	mpz_add_ui(a, rt, 1);
	mpz_pow_ui(rt, a, 2);
	mpz_sub(rt, rt, n);
	mpz_sqrt(x, rt);
	mpz_sub(p, a, x);
	mpz_add(q, a, x);

	
    mpz_out_str(stdout, 10, p);
    cout << endl;

    mpz_out_str(stdout, 10, q);
    cout << endl;
	#endif

	#if 0
	mpz_set_str(n, "648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877", 10);

	

	for(unsigned int i = 1; i < pow(2,20); ++i)
	{
		mpz_sqrt(rt, n);
		mpz_add_ui(a, rt, i);
		mpz_pow_ui(rt, a, 2);
		mpz_sub(rt, rt, n);
		mpz_sqrt(x, rt);
		mpz_sub(p, a, x);
		mpz_add(q, a, x);
		mpz_mul(rt, p, q);
		if(mpz_cmp(rt, n) == 0)
			break;
	}

	
    mpz_out_str(stdout, 10, p);
    cout << endl;
     cout << endl;

    mpz_out_str(stdout, 10, q);
    cout << endl;
     cout << endl;

     mpz_out_str(stdout, 10, rt);
    cout << endl;
     cout << endl;
	#endif

    #if 0
	mpz_set_str(n, "720062263747350425279564435525583738338084451473999841826653057981916355690188337790423408664187663938485175264994017897083524079135686877441155132015188279331812309091996246361896836573643119174094961348524639707885238799396839230364676670221627018353299443241192173812729276147530748597302192751375739387929", 10);

	mpz_mul_ui(n, n, 24);
	mpz_sqrt(rt, n);
	mpz_add_ui(a, rt, 1);
	mpz_pow_ui(rt, a, 2);
	mpz_sub(rt, rt, n);
	mpz_sqrt(x, rt);
	mpz_sub(p, a, x);

	mpz_add(q, a, x);

	mpz_mul(rt, p, q);
	mpz_cdiv_q_ui(p, p, 6);
	mpz_cdiv_q_ui(q, q, 4);
		
	
	
    mpz_out_str(stdout, 10, p);
    cout << endl;

    mpz_out_str(stdout, 10, q);
    cout << endl;
	#endif


	return 0;
}

