`timescale 1ns/10ps
`define CYCLE 10
`include "aes.v"


module testfixture();

integer fpat;
integer fgold;
integer i;
integer j;
integer gold_count = 0;
integer window [16] = '{0, 128, 256, 384,
                        1, 129, 257, 385,
                        2, 130, 258, 386,
                        3, 131, 259, 387};
integer tmp; // to store return value of $fscanf

logic CLK = 0;
logic RST = 0;
logic [127:0] plaintext;
logic [127:0] key;
logic [7:0] rom_data;
logic [7:0] rom_addr;
logic [127:0] ciphertext;
logic done;
logic [7:0] rom_mem [255:0];
logic [0:15][7:0] cipher_mem [3071:0]; // store 128 bit as 16*7 bit array
logic [1:0] rst_count;
logic [127:0] pat;
logic [127:0] golden;

typedef enum logic [1:0] { 
    RST_state, PAT_state, ENC_state, CHECK_state
}fsm;
fsm state;

// instantiation module
aes AES(
    .clk        (CLK),
    .rst        (RST),
    .plaintext  (plaintext),
    .key        (key),
    .rom_data   (rom_data),
    .rom_addr   (rom_addr),
    .ciphertext (ciphertext),
    .done       (done)
);

always begin #(`CYCLE/2) CLK = ~CLK; end

//128'h4920616d_20612070_6c61696e_74657874 // I am a plaintext
//128'h54686973_49734153_65637265_744B6579 // ThisIsASecretKey


// pattern definition
`ifdef P1
    string pattern_name = "Patter1 (I am a plaintext)";
    string PAT  [1] = '{"pat/pat1.dat"};
    string GOLD [1] = '{"golden/gold1.dat"};
    parameter pat_number = 1;
    parameter gold_num = 1;
    `define MAX_CYCLE  50000
    string header = "NONE";
    string IMG = "NONE";
    parameter plot = 0;
`elsif P2
    string pattern_name = "Patter2 (mount.bmp)";
    string PAT  [1] = '{"pat/pat2.dat"};
    string GOLD [1] = '{"golden/gold2.dat"};
    parameter pat_number = 1;
    parameter gold_num = 3072;
    `define MAX_CYCLE  20000000
    string header = "image/mount.bmp";
    string IMG = "image/Cipher_mount.bmp";
    parameter plot = 1;
`elsif P3
    string pattern_name = "Patter3 (tux.bmp)";
    string PAT  [1] = '{"pat/pat3.dat"};
    string GOLD [1] = '{"golden/gold3.dat"};
    parameter pat_number = 1;
    parameter gold_num = 3072;
    `define MAX_CYCLE  20000000
    string header = "image/tux.bmp";
    string IMG = "image/Cipher_tux.bmp";
    parameter plot = 1;
`else
    string pattern_name = "Patter Default (run all pattern)";
    string PAT  [3] = '{"pat/pat1.dat","pat/pat2.dat","pat/pat3.dat"};
    string GOLD [3] = '{"golden/gold1.dat","golden/gold2.dat","golden/gold3.dat"};
    parameter pat_number = 3;
    parameter gold_num = 1 + 3072*2;
    `define MAX_CYCLE  40000000
    string header = "NONE";
    string IMG = "NONE";
    parameter plot = 0;
`endif


// initial ROM
initial begin
    $readmemh("./pat/sbox.dat", rom_mem);
end

always @(posedge CLK) begin
    rom_data <= rom_mem[rom_addr];
end



// initial variable
initial begin
    state = RST_state;
    rst_count = 0;
end


// assign pattern from file
initial begin
    for (i=0; i<pat_number; i=i+1) begin
        fpat = $fopen(PAT[i], "r");
        if (fpat == 0) begin
            $display ("Failed open %s", PAT[i]);
            $stop;
        end
        else begin
            while (!$feof(fpat)) begin
                tmp = $fscanf(fpat, "%h\n", pat); // read one line in pat.dat file as plaintext

                @(posedge done);
            end
        end
        $fclose(fpat);
    end
end

// assign golden from file
initial begin
    for (j=0; j<pat_number; j=j+1) begin
        fgold = $fopen(GOLD[j], "r");
        if (fgold == 0) begin
            $display ("Failed open %s", GOLD[j]);
            $stop;
        end
        else begin
            while (!$feof(fgold) /*&& gold_count < gold_num*/) begin
                tmp = $fscanf(fgold, "%h\n", golden); // read one line in pat.dat file as plaintext
                gold_count = gold_count + 1;
                
                @(posedge done);
                compare(golden, ciphertext);
            end
        end
        $fclose(fgold);
    end

    $stop; // if all pattern correct
end

assign plaintext = (state == PAT_state)? pat : 'dz;
assign key       = (state == PAT_state)? 128'h54686973_49734153_65637265_744B6579 : 'dz; 

always @(posedge CLK) begin
    case (state)
        RST_state: begin // reset the system
            state <= (rst_count == 2)? PAT_state : RST_state;
            rst_count <= rst_count + 1;
            RST <= (rst_count == 2)? 0 : 1;
        end
        PAT_state: begin // feed one pattern in one cycle
            state <= ENC_state;
        end
        ENC_state: begin // wait system do encryption
            if (done) begin
                state <= PAT_state;
            end
            else begin
                state <= ENC_state;
            end
        end
    endcase
end

// out of simulation time
initial begin
    # (`MAX_CYCLE);
    $display("\n");
    $display("\n");
    $display("        ****************************               ");
    $display("        **                        **       |\__||  ");
    $display("        **  OOPS!!                **      / X,X  | ");
    $display("        **                        **    /_____   | ");
    $display("        **  Simulation Failed!!   **   /^ ^ ^ \\  |");
    $display("        **                        **  |^ ^ ^ ^ |w| ");
    $display("        ****************************   \\m___m__|_|");
    $display("\n");
    $display("Pattern name: %s", pattern_name);
    $display("!!! Reach maximum cycle number !!!");
    $stop;
end


task compare;
    input [127:0] golden;
    input [127:0] cipher;

    $write("%4d/%4d: Process...", gold_count, gold_num);

    if (golden !== cipher) begin
        $write("  Wrong!\n\n");
        //$display("Golden: %h", golden);
        $display("Golden:");
        draw_matrix(golden);
        //$display("Your Cipher text: %h", cipher);
        $display("Your Cipher text");
        draw_matrix(cipher);

        $display("\n");
        $display("\n");
        $display("        ****************************               ");
        $display("        **                        **       |\__||  ");
        $display("        **  OOPS!!                **      / X,X  | ");
        $display("        **                        **    /_____   | ");
        $display("        **  Simulation Failed!!   **   /^ ^ ^ \\  |");
        $display("        **                        **  |^ ^ ^ ^ |w| ");
        $display("        ****************************   \\m___m__|_|");
        $display("Pattern name: %s", pattern_name);
        $display("\n");
        $stop; // as soon as detect one ciphertext error
    end
    else begin
        $write("  Correct!\n");
        cipher_mem[gold_count-1] = cipher; // store cipher text into memory, generate final bmp
    end

    if (gold_count == gold_num) begin // all pattern pass, show info
        $display("\n");
        $display("\n");
        $display("        ****************************               ");
        $display("        **                        **       |\__||  ");
        $display("        **  Congratulations !!    **      / O.O  | ");
        $display("        **                        **    /_____   | ");
        $display("        **  Simulation PASS!!     **   /^ ^ ^ \\  |");
        $display("        **                        **  |^ ^ ^ ^ |w| ");
        $display("        ****************************   \\m___m__|_|");
        $display("\n");
        $display("Pattern name: %s", pattern_name);
        if(plot) plot_img();

        $fclose(fpat);
        $fclose(fgold);
        $stop();
    end
endtask

task draw_matrix;
    input [127:0] matrix;

    logic [0:15][7:0] array;
    integer i, j;
    assign array = matrix;

    // print as column major
    for (i=0; i<4; i=i+1) begin
        for (j=0; j<4; j=j+1) begin
            $write("%2h  ", array[i+4*j]);
        end
        $write("\n");
    end
    $display();
endtask

task plot_img;
    logic [7:0] inputPic_ALL [49205 : 0];
    logic [7:0] img [49151:0]; // 128*128*3 pixel
    integer iFile, iPointer, obmp;
    integer base, insert_loc;
    

    $display("Plot cipher image ...");

    // read input image
    iFile   = $fopen(header, "rb");
    iPointer = $fread(inputPic_ALL, iFile);
    $fclose(iFile);

    obmp = $fopen(IMG, "wb");
    // write header
    for(int i=0; i<54; i=i+1) begin
        $fwrite(obmp, "%c", inputPic_ALL[i]);
    end

    // resort image pixel
    for (int pat_row=0; pat_row<32; pat_row=pat_row+1) begin
        for (int pat_col=0; pat_col<32; pat_col=pat_col+1) begin
            for (int idx=0; idx<16; idx=idx+1) begin
                base = pat_col + 32*pat_row;
                insert_loc = 3*(window[idx] + 4*pat_col + 128*4*pat_row);

                img[insert_loc    ] = cipher_mem[base][idx];      // Blue
                img[insert_loc + 1] = cipher_mem[base+1024][idx]; // Green
                img[insert_loc + 2] = cipher_mem[base+2048][idx]; // Red

                //if ((insert_loc+2+54) == 'hbbac) 
                //    $display("Cipher mem: %h(base:%d, idx:%d), img: %h", cipher_mem[base+2048][idx], base, idx, insert_loc+2+54);
            end
        end
    end
    // write image pixel
    for(int i=0; i<49152; i=i+1) begin
        $fwrite(obmp, "%c", img[i]);
    end

    if(plot) $display("The image had been generated in the path: ./%s", IMG);
    $fclose(obmp);
endtask

endmodule
