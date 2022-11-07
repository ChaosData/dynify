
starti

set $state = 1

catch syscall
commands
  set $state = ! $state
  if ( !$state )
    p/x $rdi
    continue
  end
  if ( $state )
    p $rax
    continue
  end
end

continue
