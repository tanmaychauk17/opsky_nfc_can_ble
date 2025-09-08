import asyncio, zmq, zmq.asyncio

XPUB_ADDR = "tcp://127.0.0.1:5556"  
XSUB_ADDR = "tcp://127.0.0.1:5555"  

ctx = zmq.asyncio.Context.instance()

async def run_hub():
    xpub = ctx.socket(zmq.XPUB)
    xsub = ctx.socket(zmq.XSUB)

    # See subscribe/unsubscribe control frames (very useful for debugging)
    xpub.setsockopt(zmq.XPUB_VERBOSE, 1)

    xpub.bind(XPUB_ADDR); print(f"[HUB] XPUB bound -> {XPUB_ADDR}")
    xsub.bind(XSUB_ADDR); print(f"[HUB] XSUB bound -> {XSUB_ADDR}")

    async def forward_data():
        print("[HUB] data forwarder up")
        while True:
            msg = await xsub.recv_multipart()      # data from publishers
            print("[HUB] data frames=", len(msg))
            await xpub.send_multipart(msg)         # fan out to subscribers

    async def forward_subs():
        print("[HUB] subs forwarder up")
        while True:
            submsg = await xpub.recv_multipart()   # subscription control frames
            print("[HUB] sub frame:", submsg)
            await xsub.send_multipart(submsg)      # apply subs upstream

    try:
        await asyncio.gather(forward_data(), forward_subs())
    finally:
        xpub.close(0); xsub.close(0)

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_hub())
