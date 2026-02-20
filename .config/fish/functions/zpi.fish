function zpi --description "Attach to a zmx pi session named after the current directory"
    zmx attach (basename $PWD) pi
end
