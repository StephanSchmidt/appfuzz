;; Inserted into browser_cookie_log.wat by the workflow test. Encode the
;; actual incoming cookie, so neither the source nor the host plan supplies
;; a fixed copy of the leaked credential.
(func $log_hex (param $fd i32) (param $iov i32) (param i32) (param $written i32) (result i32)
    (local $i i32) (local $n i32) (local $byte i32)
    (local.set $n (i32.load (i32.add (local.get $iov) (i32.const 4))))
    (block $done
        (loop $next
            (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
            (local.set $byte (i32.load8_u (i32.add (i32.load (local.get $iov)) (local.get $i))))
            (i32.store8 (i32.add (i32.const 16000) (i32.mul (local.get $i) (i32.const 2)))
                (i32.load8_u (i32.add (i32.const 256) (i32.shr_u (local.get $byte) (i32.const 4)))))
            (i32.store8 (i32.add (i32.const 16001) (i32.mul (local.get $i) (i32.const 2)))
                (i32.load8_u (i32.add (i32.const 256) (i32.and (local.get $byte) (i32.const 15)))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $next)))
    (i32.store (i32.const 48) (i32.const 16000))
    (i32.store (i32.const 52) (i32.mul (local.get $n) (i32.const 2)))
    (call $log (local.get $fd) (i32.const 48) (i32.const 1) (local.get $written)))
(data (i32.const 256) "0123456789abcdef")
