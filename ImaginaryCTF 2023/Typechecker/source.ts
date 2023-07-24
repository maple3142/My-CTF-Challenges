/**
 * Change the flag below until it compiles correctly on TypeScript 5.1.6 :)
 */
const flag = 'ictf{who_need_javascript_when_you_can_do_it_all_in_typescript}'
/* Do not change anything below */

type notFlag1 = 'eZ!gjyTdSLcJ3{!Y_pTcMqW7qu{cMoyb04JXFHUaXx{8gTCIwIGE-AAWb1_wu32{'
type notFlag2 = 'HuuMKaxLVHVqC6NSB1Rwl2WC1F7zkxxrxAuZFpPogbBd4LGGgBfK9!eUaaSIuqJK'
type Chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{_-!}'
type SZ = 8
type M = 67
type SplitString<s extends string, ret extends string[] = []> = s extends `${infer head}${infer rest}`
	? SplitString<rest, [...ret, head]>
	: ret
type BuildTable<s extends string[], cntarr extends number[] = [], ret = {}> = cntarr['length'] extends s['length']
	? ret
	: BuildTable<s, [...cntarr, any], ret & { [_ in s[cntarr['length']]]: cntarr['length'] }>
type Tbl = BuildTable<SplitString<Chars>>
type Traslate<
	T extends { [k in string]: number },
	s extends (keyof T)[],
	ret extends number[] = []
> = ret['length'] extends s['length'] ? ret : Traslate<T, s, [...ret, T[s[ret['length']]]]>

type Equals<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2 ? true : false
type Head<A extends unknown[]> = A[0]
type Tail<A extends unknown[]> = [any, ...A][A['length']]
type FirstN<A extends unknown[], N extends number, res extends unknown[] = []> = res['length'] extends N
	? res
	: FirstN<A, N, [...res, A[res['length']]]>
type LastN<A extends unknown[], N extends number, res extends unknown[] = []> = res['length'] extends N
	? res
	: LastN<A, N, [[...res, any, ...A][A['length']], ...res]>
type RShift<A extends unknown[], Nm1 extends number> = [Tail<A>, ...FirstN<A, Nm1>]
type LShift<A extends unknown[], Nm1 extends number> = [...LastN<A, Nm1>, Head<A>]
type Gen<N extends number, ret extends unknown[] = []> = N extends ret['length'] ? ret : Gen<N, [...ret, ret['length']]>
type GenKey<N, cnt extends unknown[] = [], ret = {}> = cnt['length'] extends N
	? ret
	: GenKey<N, [...cnt, any], ret & { [_ in cnt['length']]: unknown }>
// @ts-ignore
type Dec<N extends number> = [any, ...Gen<N>][N]

type Num = Gen<M>
type Next = LShift<Num, Dec<M>>
type Prev = RShift<Num, Dec<M>>
type Add<A extends number, B extends number> = B extends 0 ? A : Add<Next[A], Prev[B]>
type Mul<A extends number, B extends number, acc extends number = 0> = B extends 0 ? acc : Mul<A, Prev[B], Add<acc, A>>

type ToMat<
	arr extends unknown[],
	N extends number = SZ,
	M extends number = SZ,
	acc extends unknown[][] = [],
	accin extends unknown[] = [],
	cnt extends unknown[] = []
> = acc['length'] extends N
	? acc
	: accin['length'] extends M
	? ToMat<arr, N, M, [...acc, accin], [], cnt>
	: ToMat<arr, N, M, acc, [...accin, arr[cnt['length']]], [...cnt, any]>
type Mat<T, N extends number, M extends number> = {
	[i in keyof GenKey<N>]: {
		[j in keyof GenKey<M>]: T
	}
}
type Sum<
	A extends ArrayLike<number>,
	ret extends number = 0,
	cnt extends unknown[] = []
> = cnt['length'] extends A['length'] ? ret : Sum<A, Add<ret, A[cnt['length']]>, [...cnt, any]>
type MatMul<
	A extends Mat<number, I, J>,
	B extends Mat<number, J, K>,
	I extends number = SZ,
	J extends number = SZ,
	K extends number = SZ
> = {
	[i in keyof GenKey<I>]: {
		[k in keyof GenKey<K>]: Sum<{
			[j in keyof GenKey<J>]: Mul<A[i][j], B[j][k]>
		} & { length: J }>
	}
}
type StrToMat<s extends string> = ToMat<Traslate<Tbl, SplitString<s>>>
type X = StrToMat<typeof flag>

function isTheFlagCorrect(good: Equals<MatMul<StrToMat<notFlag1>, X>, MatMul<X, StrToMat<notFlag2>>>, flag: string) {
	if (/^ictf{.{56}}$/.test(flag) && good) {
		console.log('Correct, the flag is', flag)
	} else {
		console.log('Wrong!')
	}
}
isTheFlagCorrect(true, flag)
