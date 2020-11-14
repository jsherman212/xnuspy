#!/usr/bin/perl

system("clang -O0 -arch arm64 -isysroot \$(xcrun --sdk iphoneos --show-sdk-path) $ARGV[0].s -o $ARGV[0]");
system("otool -jtVX $ARGV[0] | tail -n +2 > dis");

open(DISFILE, "<dis") or die("Couldn't open dis file");

open(HEADER, ">$ARGV[0]_instrs.h") or die("Couldn't open $ARGV[0]_instrs.h");

printf(HEADER "#ifndef $ARGV[0]_instrs\n");
printf(HEADER "#define $ARGV[0]_instrs\n");

my $macroname = uc("WRITE_".$ARGV[0]."_INSTRS");

printf(HEADER "#define $macroname \\\n");

my $curlabel;
my $num_instrs = 0;
my @function_starts;
# my $cur_kaddr = 0xFFFFFFF0081F8808;
# my $cur_kaddr = 0xfffffff0081f8a94;

while(my $line = <DISFILE>){
    chomp($line);

    if($line =~ /([a-f0-9]+)\s([a-f0-9]+)\s([a-f0-9]+)\s([a-f0-9]+)\s(.*)/g){
        if($curlabel){
            printf(HEADER "/*                          %-35s*/ \\\n", "$curlabel:");
        }

        my $cur_instr = "0x$4$3$2$1";
        my $cur_opcode = hex($cur_instr);

        # udf 0xffff
        if($cur_opcode == 0xffff){
            # +1 to get off of the udf 0xffff
            push(@function_starts, ($num_instrs+1)*4);
        }

        # printf(HEADER "WRITE_INSTR_TO_SCRATCH_SPACE($cur_instr); /* %#x    %-30s*/", $cur_kaddr, "$5");
        printf(HEADER "WRITE_INSTR_TO_SCRATCH_SPACE($cur_instr); /*        %-30s*/", "$5");

        $cur_kaddr += 4;
        $num_instrs += 1;

        if(eof){
            printf(HEADER " \n");
        }
        else{
            printf(HEADER " \\\n");
        }

        undef $curlabel;
    }
    elsif($line =~ /([_\w\d]+):/g){
        $curlabel = $1;
    }
}

printf(HEADER "const static int g_$ARGV[0]_num_instrs = $num_instrs;\n");

my $function_starts_length = @function_starts;

if($function_starts_length > 0){
    # printf("@function_starts, $function_starts_length\n");
    printf(HEADER "const static unsigned int g_$ARGV[0]_function_starts[] = {\n");

    foreach my $function_start (@function_starts) {
        printf(HEADER "%#x,\n", $function_start);
    }

    printf(HEADER "};\n");
    printf(HEADER "const static int g_num_$ARGV[0]_function_starts = $function_starts_length;\n");
}

printf(HEADER "#endif\n");

# clean up
system("rm ./dis");
# system("rm ./$ARGV[0]");
