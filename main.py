"""
Code samples for https://arxiv.org/abs/1906.07221
"""

import functools
import random

"""
Chapter 3. Non-Interactive Zero-Knowledge of a Polynomial
"""


### 3.2 - Factorization ###
# p(x) = t(x) * h(x)
# h(x) = p(x) / t(x)

def p_x(x): return (x**3) - (3*(x**2)) + (2*x)


def t_x(x): return (x - 1) * (x - 2)


def h_x(x): return x


# Verifier samples random r, calculates t = t(x), gives r to prover
r = random.randint(0, 32767)
t = t_x(r)

# Prover calculates h(x) = p(x) / t(x)
# evalutes p(x) and h(x) and gives values p, h to verifier
h = h_x(r)
p = p_x(r)

# Verifier checks that p = t . h
# If polynomials are equal, that means that p(x) has t(x) as a cofactor
assert p == t * h

# Of course the issues with this is that the verifier can find any combination
# of p, and h that satisifes the following property: p = t * h, e.g.
h_not = random.randint(0, 32767)
p_not = t * h_not
assert p_not == t * h_not


### 3.3.4 Encrypted Polynomial ###
# p(x) = t(x) * h(x)
# h(x) = p(x) / t(x)

polynomial_degree = 3

# Coefficients
c = [random.randint(0, 32) for i in range(polynomial_degree)]


def mod_p(x):
    """
    Modular arthimetic, a.k.a the field order
    """
    return x % 179


def E(x):
    """
    Homomorphic encryption - public key cryptography
    """
    return mod_p(7**x)


# Verifier - samples random value of S
# evaluates unencrypted t value
# calculates encryptions of s for all powers i in 0,1,...d, i.e.: E(s^i) = G**(s^i)
# t(s) = first half of the polynomial
# Sends E(s) to verifier
s = random.randint(0, 179)
t = sum([c[i]*(s**i) for i in range(polynomial_degree // 2)])
Es = [E(s**i) for i in range(polynomial_degree)]

# Prover - calculates polynomial h(x)
# Using encrypted powers, evaluate g_p and g_h
# E(p(s)) = E(s)**c where c is the coefficient

# p(x) is the whole polynomial
Ep = [mod_p(Es[i]**c[i]) for i in range(polynomial_degree)]
g_p = functools.reduce(
    lambda acc, x: mod_p(acc * x),
    Ep   
)

# h(x) is the second half of the polynomial
Eh = [mod_p(Es[i]**c[i]) for i in range(polynomial_degree // 2, polynomial_degree)]
g_h = functools.reduce(
    lambda acc, x: mod_p(acc * x),
    Eh
)

# Prover - sends g_p and g_h to verifier

# Verifier makes sure that g_p = (g_h)^(t) => g_p = E(t) * g_h
# a.k.a, p = t * h in the encrypted sdpace
assert g_p == mod_p(E(t) * g_h)
