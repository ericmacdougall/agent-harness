import time, sys
from llama_cpp import Llama

m = sys.argv[1]
t = int(sys.argv[2])
llm = Llama(model_path=m, n_ctx=2048, n_threads=t, verbose=False)
email = """Subject: Re: PO P9700742 confirmation
Hi team, we confirm PO P9700742: 4 units of ergonomic chair at $431.00 each, 2 units of desk at $120.50 each. Shipping 2011-11-02. Thanks, Sales desk"""
p = ("Extract JSON {po_number, lines:[{desc,qty,unit_price}], ship_date, intent(confirm|reject|change|other)} "
     "from this email.\n\n" + email + "\n\nJSON:")
for _ in range(2):
    s = time.time()
    o = llm.create_chat_completion(messages=[{"role": "user", "content": p}], max_tokens=160, temperature=0)
    print(m[-24:], t, round(time.time() - s, 1), "s", o["usage"],
          o["choices"][0]["message"]["content"][:100].replace("\n", " "))
