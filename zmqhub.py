"""
Copyright (C) Caterpillar Inc. All Rights Reserved.
Caterpillar: Confidential Yellow

File:        zmqhub.py
Description: Contains the logic to run the Zero Message Queue (ZMQ)HUB.
"""
import logging
import asyncio
import zmq
import zmq.asyncio

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("zmq_hub")

XPUB_ADDR = "tcp://127.0.0.1:5556"
XSUB_ADDR = "tcp://127.0.0.1:5555"

ctx = zmq.asyncio.Context.instance()

async def run_hub():
    """
    Run the ZMQ HUB
    """
    try:
        xpub = ctx.socket(zmq.XPUB)
        xsub = ctx.socket(zmq.XSUB)

        # See subscribe/unsubscribe control frames (very useful for debugging)
        xpub.setsockopt(zmq.XPUB_VERBOSE, 1)

        xpub.bind(XPUB_ADDR); logger.info(f"[HUB] XPUB bound -> {XPUB_ADDR}")
        xsub.bind(XSUB_ADDR); logger.info(f"[HUB] XSUB bound -> {XSUB_ADDR}")

        async def forward_data():
            """
            Set the data publishers forwarder
            """
            logger.info("[HUB] data forwarder up")
            while True:
                try:
                    msg = await xsub.recv_multipart()      # data from publishers
                    logger.info("[HUB] data frames=", len(msg))
                    await xpub.send_multipart(msg)         # fan out to subscribers
                except Exception as e:
                    logger.error(f"Coroutine 'forward_data' ha an exception: {e}")

        async def forward_subs():
            """
            Set the data subscribers forwarder
            """
            logger.info("[HUB] subs forwarder up")
            while True:
                try:
                    submsg = await xpub.recv_multipart()   # subscription control frames
                    logger.info(f"[HUB] sub frame: {submsg}")
                    await xsub.send_multipart(submsg)      # apply subs upstream
                except Exception as e:
                    logger.error(f"Coroutine 'forward_subs' ha an exception: {e}")
        try:
            await asyncio.gather(forward_data(), forward_subs())
        finally:
            xpub.close(0); xsub.close(0)
    except Exception as e:
        logger.error(f"Coroutine 'run_hub' ha an exception: {e}")

if __name__ == "__main__":
    asyncio.run(run_hub())
