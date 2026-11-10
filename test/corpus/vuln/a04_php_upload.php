<?php
move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . $_FILES['f']['name']);
