import numpy as np 

edges = set()
for log2_n in range(8, 16):
    n = 2 ** log2_n
    n -= 1
    m = 4 * n
    filename = f"V13E-{m}.in"
    with open(filename, 'w') as f:
        for _ in range(n): 
            f.write(f"{_+1} {_+1} 1\n")
        for _ in range(m//2):
            while True: 
                u = np.random.randint(n) + 1
                v = np.random.randint(n) + 1
                if u != v and (u, v) not in edges and (v, u) not in edges:
                    break
            edges.add((u, v))
            edges.add((v, u))
            w = np.random.randint(1, 100)
            f.write(f"{u} {v} {w}\n")
            if _ == m//2 - 1:
                f.write(f"{v} {u} {w}")
            else: 
                f.write(f"{v} {u} {w}\n")