
starti ./static static

set $state = 1

b inner
commands
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
end

continue
