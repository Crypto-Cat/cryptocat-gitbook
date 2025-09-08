---
name: Comparing (2025)
event: Imaginary CTF 2025
category: Rev
description: Writeup for Comparing (Rev) - Imaginary CTF (2025) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Comparing

## Description

> I put my flag into this program, but now I lost the flag. Here is the program, and the output. Could you use it to find the flag?

## Solution

The challenge comes with two files; `comparing.cpp` and `output.txt` - let's check them out, I'll get ChatGPT to generate some comments to make our life easy.

### Source Code

#### comparing.cpp

{% code overflow="wrap" %}
```cpp
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <numeric>
#include <map>
#include <cmath>
#include <set>
#include <fstream>
#include <queue>
#include <unordered_map>
#include <cstring>
#include <list>
#include <cassert>
#include <tuple>
using namespace std;

// Comparator used for the priority_queue.
// It ensures tuples with *larger ASCII sums* come out first.
class Compare {
public:
    bool operator()(tuple<char, char, int> a, tuple<char, char, int> b) {
        return static_cast<int>(get<0>(a)) + static_cast<int>(get<1>(a)) >
               static_cast<int>(get<0>(b)) + static_cast<int>(get<1>(b));
    }
};

// Called for pairs whose index is EVEN.
// Takes ASCII of val1 and val3 and the index, concatenates them,
// then appends the reversed digits of (val1||val3).
string even(int val1, int val3, int ii) {
    string out = to_string(val1) + to_string(val3) + to_string(ii);
    string x   = to_string(val1) + to_string(val3);
    for (int i = x.size() - 1; i >= 0; i--) {
        out += x[i];
    }
    return out;
}

// Called for pairs whose index is ODD.
// Concatenates ASCII of val1, val3, and index into an integer string.
// There is a dummy sum/subtract loop that cancels to zero.
string odd(int val1, int val3, int ii) {
    int out = stoi(to_string(val1) + to_string(val3) + to_string(ii));
    int i = 0;
    int addend = 0;

    // Adds 0..99 then subtracts 99..0, so net effect = 0.
    while (i < 100) { addend += i; i++; }
    i--;
    while (i >= 0) { addend -= i; i--; }

    return to_string(out + addend);
}

int main() {
    // The hidden flag in the original challenge.
    // Here it is redacted — in the real challenge, this is the secret input.
    string flag = "REDACTED";

    // Break flag into pairs: (c0,c1,0), (c2,c3,1), ...
    priority_queue<tuple<char, char, int>, vector<tuple<char, char, int>>, Compare> pq;
    for (int i = 0; i < flag.size() / 2; i++) {
        tuple<char, char, int> x = { flag[i * 2], flag[i * 2 + 1], i };
        pq.push(x);
    }

    vector<string> out;

    // Process pairs two at a time.
    while (!pq.empty()) {
        // First tuple
        int val1 = static_cast<int>(get<0>(pq.top()));
        int val2 = static_cast<int>(get<1>(pq.top()));
        int i1   = get<2>(pq.top());
        pq.pop();

        // Second tuple
        int val3 = static_cast<int>(get<0>(pq.top()));
        int val4 = static_cast<int>(get<1>(pq.top()));
        int i2   = get<2>(pq.top());
        pq.pop();

        // Transform depending on whether original index was even/odd
        if (i1 % 2 == 0) { out.push_back(even(val1, val3, i1)); }
        else             { out.push_back(odd(val1, val3, i1)); }

        if (i2 % 2 == 0) { out.push_back(even(val2, val4, i2)); }
        else             { out.push_back(odd(val2, val4, i2)); }
    }

    // Print all output lines (this matches output.txt in the challenge).
    for (int i = 0; i < out.size(); i++) {
        cout << out[i] << endl;
    }

    return 0;
}
```
{% endcode %}

#### output.txt

{% code overflow="wrap" %}
```
9548128459
491095
1014813
561097
10211614611201
5748108475
1171123
516484615
114959
649969946
1051160611501
991021
1231012101321
9912515
11411511
1151164611511
```
{% endcode %}

We just need to reverse the input algorithm, and feed it the output to retrieve the redacted flag.

### PoC (solve.py)

{% code overflow="wrap" %}
```python
def gen_even(a, b, idx):
    s = str(a)+str(b)
    return s+str(idx)+s[::-1]

def gen_odd(a, b, idx):
    return str(int(str(a)+str(b)+str(idx)))

def crack_line(s):
    for a in range(32, 127):
        for b in range(32, 127):
            for idx in range(64):
                if gen_even(a, b, idx) == s or gen_odd(a, b, idx) == s:
                    return a, b, idx
    raise ValueError("no match")

lines = [l.strip()
         for l in open("output.txt", "r").read().splitlines() if l.strip()]
triples = [crack_line(l) for l in lines]

max_idx = max(t[2] for t in triples)
c1 = ["?"]*(max_idx+1)
c2 = ["?"]*(max_idx+1)

for i in range(0, len(triples), 2):
    a1, b1, i1 = triples[i]
    a2, b2, i2 = triples[i+1]
    c1[i1] = chr(a1)
    c2[i1] = chr(a2)
    c1[i2] = chr(b1)
    c2[i2] = chr(b2)

flag = "".join(c1[i]+c2[i] for i in range(max_idx+1))
print(flag)
```
{% endcode %}

{% code overflow="wrap" %}
```bash
python solve.py

ictf{cu3st0m_c0mp@r@t0rs_1e8f9e}
```
{% endcode %}

Flag: `ictf{cu3st0m_c0mp@r@t0rs_1e8f9e}`
