# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import threading
import time
import subprocess
import logging

logger = logging.getLogger(__name__)

class KeywordUpdater:
    def __init__(self):
        self.updater_thread = None
        self.running = False
        
    def start(self):
        if not self.running:
            self.running = True
            self.updater_thread = threading.Thread(
                target=self._updater_loop, 
                daemon=True,
                name="KeywordUpdater"
            )
            self.updater_thread.start()
            logger.info("Background keyword updater started")
            
    def stop(self):
        self.running = False
        if self.updater_thread:
            self.updater_thread.join(timeout=5)
            logger.info("Keyword updater stopped")
            
    def _updater_loop(self):
        while self.running:
            current_hour = time.localtime().tm_hour

            if 1 <= current_hour <= 5:
                logger.info("Night time - running keyword update...")
                self._run_update()
                time.sleep(4 * 3600)
            else:
                time.sleep(1800)  # 30 minutes
                
    def _run_update(self):
        try:
            result = subprocess.run(
                ['python3', 'malicious_keywords_updater.py', '--mode', 'once', '--cleanup-days', '180'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("Keyword update successful")
            else:
                logger.error(f"Keyword update failed: {result.stderr[:200]}")
                
        except subprocess.TimeoutExpired:
            logger.error("Keyword update timed out after 5 minutes")
        except Exception as e:
            logger.error(f"Error running keyword updater: {e}")
            
    def manual_update(self):
        logger.info("Manual keyword update requested")
        self._run_update()
