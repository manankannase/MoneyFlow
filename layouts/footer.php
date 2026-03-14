<?php
/**
 * Page Footer Template
 * Included at the end of every page
 */
?>
        </main>
        <footer class="page-footer">
            <div class="footer-content">
                <p class="footer-text">&copy; <?php echo date('Y'); ?> MoneyFlow - Secure Fund Transfer Platform</p>
                <p class="footer-info">
                    Secure transactions powered by AES-256-GCM &amp; Argon2id
                </p>
            </div>
        </footer>
    </div>
    <?php $mainJsPath = $_SERVER['DOCUMENT_ROOT'] . '/js/main.js'; ?>
    <script src="/js/main.js?v=<?php echo file_exists($mainJsPath) ? filemtime($mainJsPath) : '1'; ?>"></script>
</body>
</html>
